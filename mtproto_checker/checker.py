from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import random
import sys
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, unquote, urlparse


DEFAULT_TIMEOUT = 12.0
DEFAULT_CONCURRENCY = 10
DEFAULT_ATTEMPTS = 2
DEFAULT_MIN_SUCCESSES = 1
TELEGRAM_DC_HOST = "149.154.167.50"
TELEGRAM_DC_PORT = 443
TELEGRAM_DCS = (
    ("149.154.175.53", 443),
    ("149.154.167.51", 443),
    ("149.154.175.100", 443),
    ("149.154.167.91", 443),
    ("149.154.171.5", 443),
)
TELEGRAM_DC_IDS = (1, 2, 3, 4, 5)
REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
MTTRANSPORT_INTERMEDIATE = b"\xee\xee\xee\xee"
MTTRANSPORT_ABRIDGED = b"\xef\xef\xef\xef"
MTTRANSPORT_PADDED_INTERMEDIATE = b"\xdd\xdd\xdd\xdd"
SYSTEM_RANDOM = random.SystemRandom()


class ProxyStatus(str, Enum):
    LIVE = "live"
    DEAD = "dead"
    INVALID = "invalid"


@dataclass(frozen=True)
class ProxyTarget:
    raw_url: str
    kind: str
    server: str
    port: int
    secret: str | None = None
    username: str | None = None
    password: str | None = None


@dataclass(frozen=True)
class CheckResult:
    url: str
    server: str | None
    port: int | None
    status: ProxyStatus
    latency_ms: float | None
    error: str | None = None
    attempts: int = 1
    successes: int = 0

    @property
    def alive(self) -> bool:
        return self.status == ProxyStatus.LIVE


def parse_proxy_url(proxy_url: str) -> ProxyTarget:
    raw_url = proxy_url.strip()
    if not raw_url:
        raise ValueError("empty URL")

    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)
    path = parsed.path.strip("/")

    server = (query.get("server", [None])[0] or parsed.hostname or parsed.netloc).strip()
    port_text = query.get("port", [None])[0]
    secret = query.get("secret", [None])[0]
    username = query.get("user", [None])[0]
    password = query.get("pass", [None])[0]
    kind = "mtproto" if secret else "tcp"

    if path == "socks" or parsed.scheme.startswith("socks"):
        kind = "socks5"

    # Support simple host:port input in addition to tg://proxy?... links.
    if not port_text and parsed.port:
        port_text = str(parsed.port)
    if not port_text and ":" in raw_url and "://" not in raw_url:
        server_part, port_part = raw_url.rsplit(":", 1)
        server = server_part.strip()
        port_text = port_part.strip()

    if not server:
        raise ValueError("missing server")
    if not port_text:
        raise ValueError("missing port")

    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid port: {port_text}") from exc

    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")

    return ProxyTarget(
        raw_url=raw_url,
        kind=kind,
        server=unquote(server),
        port=port,
        secret=secret,
        username=username,
        password=password,
    )


async def check_proxy(
    proxy_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    attempts: int = DEFAULT_ATTEMPTS,
    min_successes: int = DEFAULT_MIN_SUCCESSES,
) -> CheckResult:
    try:
        target = parse_proxy_url(proxy_url)
    except ValueError as exc:
        return CheckResult(
            url=proxy_url.strip(),
            server=None,
            port=None,
            status=ProxyStatus.INVALID,
            latency_ms=None,
            error=str(exc),
            attempts=0,
            successes=0,
        )

    started = time.perf_counter()
    attempts = max(1, attempts)
    min_successes = max(1, min(min_successes, attempts))
    successes = 0
    last_error: str | None = None
    successful_latency_ms: float | None = None

    for attempt_index in range(attempts):
        attempt_started = time.perf_counter()
        try:
            await _check_target_once(target, timeout)
            successes += 1
            successful_latency_ms = (time.perf_counter() - attempt_started) * 1000
            if successes >= min_successes:
                return CheckResult(
                    url=target.raw_url,
                    server=target.server,
                    port=target.port,
                    status=ProxyStatus.LIVE,
                    latency_ms=round(successful_latency_ms, 1),
                    error=None,
                    attempts=attempt_index + 1,
                    successes=successes,
                )
        except (OSError, EOFError, asyncio.TimeoutError, ConnectionError) as exc:
            last_error = type(exc).__name__
        except (RuntimeError, ValueError) as exc:
            return CheckResult(
                url=target.raw_url,
                server=target.server,
                port=target.port,
                status=ProxyStatus.INVALID,
                latency_ms=None,
                error=str(exc),
                attempts=attempt_index + 1,
                successes=successes,
            )

    latency_ms = (time.perf_counter() - started) * 1000
    return CheckResult(
        url=target.raw_url,
        server=target.server,
        port=target.port,
        status=ProxyStatus.DEAD,
        latency_ms=round(latency_ms, 1),
        error=last_error or "not enough successful attempts",
        attempts=attempts,
        successes=successes,
    )


async def _check_target_once(target: ProxyTarget, timeout: float) -> None:
    writer: asyncio.StreamWriter | None = None

    try:
        if target.kind == "socks5":
            await _check_socks5_target(target, timeout)
            return

        if target.kind == "mtproto":
            await _check_mtproto_target(target, timeout)
            return

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.server, target.port),
            timeout=timeout,
        )

        await _check_tcp(reader, writer, timeout)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _make_mtproto_like_probe() -> bytes:
    while True:
        probe = bytearray(os.urandom(64))
        if probe[0] != 0xEF and probe[:4] != b"\x00\x00\x00\x00":
            break
    probe[56] = 0xEF
    return bytes(probe)


def _decode_secret(secret: str | None) -> bytes:
    if not secret:
        raise ValueError("missing MTProto secret")

    clean = secret.strip()
    try:
        return bytes.fromhex(clean)
    except ValueError:
        padding = "=" * ((4 - len(clean) % 4) % 4)
        return base64.urlsafe_b64decode(clean + padding)


def _secret_mode(secret: bytes) -> str:
    if len(secret) >= 17 and secret[0] == 0xEE:
        return "fake_tls"
    if len(secret) >= 17 and secret[0] == 0xDD:
        return "secure"
    return "plain"


def _secret_key(secret: bytes) -> bytes:
    if len(secret) >= 17 and secret[0] in {0xDD, 0xEE}:
        return secret[1:17]
    if len(secret) >= 16:
        return secret[:16]
    raise ValueError("MTProto secret must contain at least 16 bytes")


def _secret_sni(secret: bytes) -> str:
    if len(secret) > 17:
        try:
            return secret[17:].decode("utf-8")
        except UnicodeDecodeError:
            pass
    return "www.google.com"


class ObfuscatedStream:
    def __init__(
        self,
        reader,
        writer: asyncio.StreamWriter | "TLSAppDataWriter",
        secret: bytes,
        protocol: bytes,
        dc_id: int,
    ) -> None:
        try:
            from Crypto.Cipher import AES
        except ImportError as exc:
            raise RuntimeError("pycryptodome is required for MTProto checks") from exc

        init = _make_obfuscation_init(protocol, dc_id)
        reverse_init = bytes(init)[::-1]
        key = hashlib.sha256(bytes(init[8:40]) + _secret_key(secret)).digest()
        iv = bytes(init[40:56])
        decrypt_key = hashlib.sha256(reverse_init[8:40] + _secret_key(secret)).digest()
        decrypt_iv = reverse_init[40:56]

        self.reader = reader
        self.writer = writer
        self.encrypt_cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
        self.decrypt_cipher = AES.new(
            decrypt_key,
            AES.MODE_CTR,
            nonce=b"",
            initial_value=int.from_bytes(decrypt_iv, "big"),
        )

        encrypted_init = self.encrypt_cipher.encrypt(bytes(init))
        init[56:64] = encrypted_init[56:64]
        self.init_payload = bytes(init)

    async def start(self, timeout: float) -> None:
        self.writer.write(self.init_payload)
        await asyncio.wait_for(self.writer.drain(), timeout=timeout)

    def write(self, data: bytes) -> None:
        self.writer.write(self.encrypt_cipher.encrypt(data))

    async def drain(self, timeout: float) -> None:
        await asyncio.wait_for(self.writer.drain(), timeout=timeout)

    async def read_exactly(self, size: int, timeout: float) -> bytes:
        data = await asyncio.wait_for(self.reader.readexactly(size), timeout=timeout)
        return self.decrypt_cipher.decrypt(data)


class TLSAppDataReader:
    def __init__(self, reader: asyncio.StreamReader) -> None:
        self.reader = reader
        self.buffer = bytearray()

    async def readexactly(self, size: int) -> bytes:
        while len(self.buffer) < size:
            record = await self._read_record()
            if record[0] == 0x14:
                continue
            if record[0] != 0x17:
                raise ConnectionError(f"unexpected TLS record type: {record[0]:02x}")
            self.buffer.extend(record[5:])
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    async def _read_record(self) -> bytes:
        header = await self.reader.readexactly(5)
        length = int.from_bytes(header[3:5], "big")
        payload = await self.reader.readexactly(length)
        return header + payload


class TLSAppDataWriter:
    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self.writer = writer
        self.first_packet = True

    def write(self, data: bytes) -> None:
        if self.first_packet:
            self.writer.write(b"\x14\x03\x03\x00\x01\x01")
            self.first_packet = False
        for start in range(0, len(data), 16384):
            chunk = data[start : start + 16384]
            self.writer.write(b"\x17\x03\x03" + len(chunk).to_bytes(2, "big") + chunk)

    async def drain(self) -> None:
        await self.writer.drain()

    def close(self) -> None:
        self.writer.close()

    async def wait_closed(self) -> None:
        await self.writer.wait_closed()


def _make_obfuscation_init(protocol: bytes, dc_id: int) -> bytearray:
    if len(protocol) != 4:
        raise ValueError("protocol id must be exactly 4 bytes")

    while True:
        init = bytearray(os.urandom(64))
        first_int = bytes(init[:4])
        second_int = bytes(init[4:8])
        if init[0] == 0xEF:
            continue
        if first_int in {
            b"\xdd\xdd\xdd\xdd",
            b"\xee\xee\xee\xee",
            b"POST",
            b"GET ",
            b"HEAD",
            b"\x16\x03\x01\x02",
        }:
            continue
        if second_int == b"\x00\x00\x00\x00":
            continue
        break

    init[56:60] = protocol
    init[60:62] = int(dc_id).to_bytes(2, "little", signed=True)
    return init


def _make_mtproxy_obfuscated_init(secret: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise RuntimeError("pycryptodome is required for MTProto checks") from exc

    protocol = b"\xdd\xdd\xdd\xdd"
    dc = b"\x02\x00\x00\x00"

    while True:
        init = bytearray(os.urandom(64))
        first_int = bytes(init[:4])
        second_int = bytes(init[4:8])
        if init[0] == 0xEF:
            continue
        if first_int in {
            b"\xdd\xdd\xdd\xdd",
            b"\xee\xee\xee\xee",
            b"POST",
            b"GET ",
            b"HEAD",
            b"\x16\x03\x01\x02",
        }:
            continue
        if second_int == b"\x00\x00\x00\x00":
            continue
        break

    init[56:60] = protocol
    init[60:64] = dc

    key = hashlib.sha256(bytes(init[8:40]) + _secret_key(secret)).digest()
    iv = bytes(init[40:56])
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    encrypted = cipher.encrypt(bytes(init))
    init[56:64] = encrypted[56:64]
    return bytes(init)


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key=key, msg=msg, digestmod=hashlib.sha256).digest()


def _fake_x25519_public_key() -> bytes:
    # Matches the lightweight placeholder approach used by Telegram FakeTLS
    # checkers. The proxy authenticates the ClientHello with HMAC, not with a
    # real TLS key exchange.
    p25519 = 2**255 - 19
    value = SYSTEM_RANDOM.randrange(p25519)
    return int.to_bytes((value * value) % p25519, length=32, byteorder="little")


def _make_grease(size: int = 7) -> bytes:
    grease = bytearray()
    while len(grease) < size:
        value = (SYSTEM_RANDOM.randrange(256) & 0xF0) + 0x0A
        if grease and grease[-1] == value:
            value ^= 0x10
        grease.append(value)
    return bytes(grease)


def _make_fake_tls_client_hello(sni: str, secret_key: bytes) -> tuple[bytes, bytes, bytes]:
    grease = _make_grease()
    session_id = os.urandom(32)
    server_name = sni.encode("idna")[:255]
    key_share = _fake_x25519_public_key()
    ml_kem_placeholder = os.urandom(1184)

    data = bytearray()
    scopes: list[int] = []

    def put(blob: bytes) -> None:
        data.extend(blob)

    def begin_scope() -> None:
        scopes.append(len(data))
        data.extend(b"\x00\x00")

    def end_scope() -> None:
        start = scopes.pop()
        size = len(data) - start - 2
        data[start : start + 2] = size.to_bytes(2, "big")

    def grease_pair(seed: int) -> None:
        value = grease[seed]
        put(bytes((value, value)))

    def sni_part() -> None:
        put(b"\x00\x00")
        begin_scope()
        begin_scope()
        put(b"\x00")
        begin_scope()
        put(server_name)
        end_scope()
        end_scope()
        end_scope()

    def ech_part() -> None:
        put(b"\xfe\x0d")
        begin_scope()
        put(b"\x00\x00\x01\x00\x01")
        put(os.urandom(1))
        put(b"\x00\x20")
        put(os.urandom(32))
        begin_scope()
        put(os.urandom(SYSTEM_RANDOM.randrange(0, 4) * 32 + 144))
        end_scope()
        end_scope()

    def key_share_part() -> None:
        put(b"\x00\x33\x04\xef\x04\xed")
        grease_pair(4)
        put(b"\x00\x01\x00\x11\xec\x04\xc0")
        put(ml_kem_placeholder)
        put(key_share)
        put(b"\x00\x1d\x00\x20")
        put(_fake_x25519_public_key())

    def padding() -> None:
        size = 513 - len(data)
        if size > 0:
            put(b"\x00\x15")
            begin_scope()
            put(b"\x00" * size)
            end_scope()

    extension_parts = [
        sni_part,
        lambda: put(b"\x00\x05\x00\x05\x01\x00\x00\x00\x00"),
        lambda: (put(b"\x00\x0a\x00\x0c\x00\x0a"), grease_pair(4), put(b"\x11\xec\x00\x1d\x00\x17\x00\x18")),
        lambda: put(b"\x00\x0b\x00\x02\x01\x00"),
        lambda: put(b"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01"),
        lambda: put(b"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31"),
        lambda: put(b"\x00\x12\x00\x00"),
        lambda: put(b"\x00\x17\x00\x00"),
        lambda: put(b"\x00\x1b\x00\x03\x02\x00\x02"),
        lambda: put(b"\x00\x23\x00\x00"),
        lambda: (put(b"\x00\x2b\x00\x07\x06"), grease_pair(6), put(b"\x03\x04\x03\x03")),
        lambda: put(b"\x00\x2d\x00\x02\x01\x01"),
        key_share_part,
        lambda: put(b"\x44\xcd\x00\x05\x00\x03\x02\x68\x32"),
        ech_part,
        lambda: put(b"\xff\x01\x00\x01\x00"),
    ]
    SYSTEM_RANDOM.shuffle(extension_parts)

    put(b"\x16\x03\x01")
    begin_scope()
    put(b"\x01\x00")
    begin_scope()
    put(b"\x03\x03")
    random_offset = len(data)
    put(b"\x00" * 32)
    put(b"\x20")
    put(session_id)
    put(
        b"\x00\x20"
        + bytes((grease[0], grease[0]))
        + b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
        + b"\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"
    )
    begin_scope()
    grease_pair(2)
    put(b"\x00\x00")
    for part in extension_parts:
        part()
    grease_pair(3)
    put(b"\x00\x01\x00")
    padding()
    end_scope()
    end_scope()
    end_scope()

    zero_random_packet = bytes(data)
    digest = _hmac_sha256(secret_key, zero_random_packet)
    current_time = int(time.time()).to_bytes(4, "little")
    xored_time = bytes(current_time[i] ^ digest[28 + i] for i in range(4))
    client_random = digest[:28] + xored_time
    data[random_offset : random_offset + 32] = client_random
    return bytes(data), session_id, client_random


def _iter_tls_records(data: bytes) -> list[bytes]:
    records = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 5:
            raise ValueError("incomplete TLS record header")
        record_len = int.from_bytes(data[offset + 3 : offset + 5], "big")
        next_offset = offset + 5 + record_len
        if next_offset > len(data):
            raise ValueError("incomplete TLS record payload")
        records.append(data[offset:next_offset])
        offset = next_offset
    return records


def _verify_fake_tls_server_hello(
    server_hello: bytes,
    secret_key: bytes,
    session_id: bytes,
    client_random: bytes,
) -> None:
    try:
        records = _iter_tls_records(server_hello)
    except ValueError as exc:
        raise ConnectionError("invalid FakeTLS ServerHello records") from exc

    if len(records) < 2:
        raise ConnectionError("FakeTLS ServerHello is incomplete")
    if records[0][:3] != b"\x16\x03\x03":
        raise ConnectionError("FakeTLS first record is not ServerHello")
    if any(record[1:3] != b"\x03\x03" for record in records):
        raise ConnectionError("FakeTLS record version mismatch")
    if records[-1][:1] != b"\x17":
        raise ConnectionError("FakeTLS handoff application-data record is missing")
    if any(record[:1] not in (b"\x14", b"\x17") for record in records[1:]):
        raise ConnectionError("FakeTLS ServerHello contains unexpected record type")

    handshake_payload = records[0][5:]
    if len(handshake_payload) < 39 or handshake_payload[:1] != b"\x02":
        raise ConnectionError("FakeTLS handshake payload is not ServerHello")
    server_session_len = handshake_payload[38]
    server_session_id = handshake_payload[39 : 39 + server_session_len]
    if server_session_id != session_id:
        raise ConnectionError("FakeTLS ServerHello session_id mismatch")

    server_digest = server_hello[11:43]
    zeroed = bytearray(server_hello)
    zeroed[11:43] = b"\x00" * 32
    expected_digest = _hmac_sha256(secret_key, client_random + bytes(zeroed))
    if server_digest != expected_digest:
        raise ConnectionError("FakeTLS ServerHello HMAC mismatch")


async def _read_fake_tls_server_hello(
    reader: asyncio.StreamReader,
    timeout: float,
) -> bytes:
    records = []
    deadline_timeout = max(timeout, 10.0)
    first = await asyncio.wait_for(reader.readexactly(5), timeout=deadline_timeout)
    first_payload = await asyncio.wait_for(
        reader.readexactly(int.from_bytes(first[3:5], "big")),
        timeout=deadline_timeout,
    )
    if first[:1] != b"\x16":
        raise ConnectionError(f"unexpected first FakeTLS record type: {first[:1].hex()}")
    records.append(first + first_payload)

    while True:
        header = await asyncio.wait_for(reader.readexactly(5), timeout=deadline_timeout)
        payload = await asyncio.wait_for(
            reader.readexactly(int.from_bytes(header[3:5], "big")),
            timeout=deadline_timeout,
        )
        record = header + payload
        records.append(record)
        if header[:1] == b"\x17":
            return b"".join(records)
        if header[:1] != b"\x14":
            raise ConnectionError(f"unexpected FakeTLS record type: {header[:1].hex()}")


def _make_legacy_fake_tls_client_hello(sni: str) -> bytes:
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    cipher_suites = bytes.fromhex(
        "130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"
    )
    compression = b"\x00"

    server_name = sni.encode("idna")
    server_name_ext_body = (
        len(server_name + b"\x00\x00\x00").to_bytes(2, "big")
        + b"\x00"
        + len(server_name).to_bytes(2, "big")
        + server_name
    )
    server_name_ext = b"\x00\x00" + len(server_name_ext_body).to_bytes(2, "big") + server_name_ext_body
    supported_groups = bytes.fromhex("000a00080006001d00170018")
    ec_point_formats = bytes.fromhex("000b00020100")
    signature_algorithms = bytes.fromhex("000d0012001004030804040105030805050108060601")
    supported_versions = bytes.fromhex("002b0003020304")
    key_share = b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20" + os.urandom(32)
    extensions = (
        server_name_ext
        + supported_groups
        + ec_point_formats
        + signature_algorithms
        + supported_versions
        + key_share
    )

    body = (
        b"\x03\x03"
        + random_bytes
        + bytes([len(session_id)])
        + session_id
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + bytes([len(compression)])
        + compression
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


async def _check_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
) -> None:
    writer.write(os.urandom(8))
    await asyncio.wait_for(writer.drain(), timeout=timeout)
    try:
        data = await asyncio.wait_for(reader.read(1), timeout=0.5)
        if data == b"":
            raise ConnectionResetError("connection closed after TCP probe")
    except asyncio.TimeoutError:
        return


async def _check_mtproto(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target: ProxyTarget,
    timeout: float,
) -> None:
    secret = _decode_secret(target.secret)
    mode = _secret_mode(secret)

    if mode == "fake_tls":
        await _check_fake_tls_mtproto(reader, writer, secret, timeout)
        return

    await _check_obfuscated_mtproto(reader, writer, secret, timeout)


async def _check_mtproto_target(target: ProxyTarget, timeout: float) -> None:
    secret = _decode_secret(target.secret)
    mode = _secret_mode(secret)

    if mode == "fake_tls":
        await _check_fake_tls_mtproto_target(target, secret, timeout)
        return

    errors: list[str] = []
    transport_candidates = [
        ("intermediate", MTTRANSPORT_INTERMEDIATE, _encode_intermediate_packet, _read_intermediate_packet),
        ("abridged", MTTRANSPORT_ABRIDGED, _encode_abridged_packet, _read_abridged_packet),
        (
            "padded_intermediate",
            MTTRANSPORT_PADDED_INTERMEDIATE,
            _encode_padded_intermediate_packet,
            _read_padded_intermediate_packet,
        ),
    ]
    if mode == "secure":
        transport_candidates = [transport_candidates[2], transport_candidates[0]]

    for dc_id in TELEGRAM_DC_IDS:
        for transport_name, protocol, encoder, decoder in transport_candidates:
            reader = None
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.server, target.port),
                    timeout=timeout,
                )
                await _check_obfuscated_mtproto_connection(
                    reader,
                    writer,
                    secret,
                    timeout,
                    dc_id=dc_id,
                    protocol=protocol,
                    encoder=encoder,
                    decoder=decoder,
                )
                return
            except Exception as exc:
                errors.append(f"dc{dc_id}/{transport_name}: {type(exc).__name__}")
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

    raise ConnectionError("; ".join(errors[-6:]) or "MTProto req_pq_multi failed")


async def _check_fake_tls_mtproto_target(
    target: ProxyTarget,
    secret: bytes,
    timeout: float,
) -> None:
    errors: list[str] = []
    transport_candidates = [
        ("faketls-padded", MTTRANSPORT_PADDED_INTERMEDIATE, _encode_padded_intermediate_packet, _read_padded_intermediate_packet),
        ("faketls-intermediate", MTTRANSPORT_INTERMEDIATE, _encode_intermediate_packet, _read_intermediate_packet),
        ("faketls-abridged", MTTRANSPORT_ABRIDGED, _encode_abridged_packet, _read_abridged_packet),
    ]

    for dc_id in TELEGRAM_DC_IDS:
        for transport_name, protocol, encoder, decoder in transport_candidates:
            reader = None
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.server, target.port),
                    timeout=timeout,
                )
                await _check_fake_tls_mtproto(
                    reader,
                    writer,
                    secret,
                    timeout,
                    dc_id=dc_id,
                    protocol=protocol,
                    encoder=encoder,
                    decoder=decoder,
                )
                return
            except Exception as exc:
                errors.append(f"dc{dc_id}/{transport_name}: {type(exc).__name__}")
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

    raise ConnectionError("; ".join(errors[-6:]) or "FakeTLS MTProto req_pq_multi failed")


def _mtproto_message_id() -> int:
    now = time.time()
    return (int(now) << 32) | (int((now - int(now)) * 1_000_000) << 10)


def _make_req_pq_multi_body(nonce: bytes) -> bytes:
    return REQ_PQ_MULTI.to_bytes(4, "little") + nonce


def _make_unencrypted_mtproto_message(body: bytes) -> bytes:
    return (
        b"\x00" * 8
        + _mtproto_message_id().to_bytes(8, "little")
        + len(body).to_bytes(4, "little")
        + body
    )


def _encode_intermediate_packet(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


def _encode_abridged_packet(payload: bytes) -> bytes:
    length_words = len(payload) // 4
    if len(payload) % 4:
        raise ValueError("abridged MTProto payload length must be divisible by 4")
    if length_words < 127:
        return bytes([length_words]) + payload
    return b"\x7f" + length_words.to_bytes(3, "little") + payload


def _encode_padded_intermediate_packet(payload: bytes) -> bytes:
    padding_len = random.randint(0, 3)
    padding = os.urandom(padding_len)
    return _encode_intermediate_packet(payload + padding)


async def _read_intermediate_packet(stream: ObfuscatedStream, timeout: float) -> bytes:
    length = int.from_bytes(await stream.read_exactly(4, timeout), "little")
    if length <= 0 or length > 1_048_576:
        raise ConnectionError(f"invalid MTProto intermediate packet length: {length}")
    return await stream.read_exactly(length, timeout)


async def _read_padded_intermediate_packet(stream: ObfuscatedStream, timeout: float) -> bytes:
    packet = await _read_intermediate_packet(stream, timeout)
    padding_len = len(packet) % 4
    if padding_len:
        return packet[:-padding_len]
    return packet


async def _read_abridged_packet(stream: ObfuscatedStream, timeout: float) -> bytes:
    first = (await stream.read_exactly(1, timeout))[0]
    if first < 127:
        length_words = first
    else:
        length_words = int.from_bytes(await stream.read_exactly(3, timeout), "little")
    length = length_words * 4
    if length <= 0 or length > 1_048_576:
        raise ConnectionError(f"invalid MTProto abridged packet length: {length}")
    return await stream.read_exactly(length, timeout)


def _validate_res_pq(payload: bytes, nonce: bytes) -> None:
    if len(payload) < 20:
        raise ConnectionError("MTProto response is too short")

    auth_key_id = payload[:8]
    if auth_key_id != b"\x00" * 8:
        raise ConnectionError("MTProto response has unexpected auth_key_id")

    body_len = int.from_bytes(payload[16:20], "little")
    body = payload[20 : 20 + body_len]
    if len(body) < body_len:
        raise ConnectionError("MTProto response body is incomplete")

    constructor = int.from_bytes(body[:4], "little")
    if constructor != RES_PQ:
        raise ConnectionError(f"unexpected MTProto constructor: 0x{constructor:08x}")
    if body[4:20] != nonce:
        raise ConnectionError("MTProto resPQ nonce mismatch")


async def _check_obfuscated_mtproto(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter | TLSAppDataWriter,
    secret: bytes,
    timeout: float,
) -> None:
    await _check_obfuscated_mtproto_connection(
        reader,
        writer,
        secret,
        timeout,
        dc_id=2,
        protocol=MTTRANSPORT_INTERMEDIATE,
        encoder=_encode_intermediate_packet,
        decoder=_read_intermediate_packet,
    )


async def _check_obfuscated_mtproto_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter | TLSAppDataWriter,
    secret: bytes,
    timeout: float,
    *,
    dc_id: int,
    protocol: bytes,
    encoder,
    decoder,
) -> None:
    nonce = os.urandom(16)
    stream = ObfuscatedStream(reader, writer, secret, protocol, dc_id)
    await stream.start(timeout)
    stream.write(encoder(_make_unencrypted_mtproto_message(_make_req_pq_multi_body(nonce))))
    await stream.drain(timeout)
    response = await decoder(stream, timeout)
    _validate_res_pq(response, nonce)


async def _check_fake_tls_mtproto(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    secret: bytes,
    timeout: float,
    *,
    dc_id: int = 2,
    protocol: bytes = MTTRANSPORT_PADDED_INTERMEDIATE,
    encoder=_encode_padded_intermediate_packet,
    decoder=_read_padded_intermediate_packet,
) -> None:
    client_hello, session_id, client_random = _make_fake_tls_client_hello(
        _secret_sni(secret),
        _secret_key(secret),
    )
    writer.write(client_hello)
    await asyncio.wait_for(writer.drain(), timeout=timeout)
    server_hello = await _read_fake_tls_server_hello(reader, timeout)
    _verify_fake_tls_server_hello(
        server_hello,
        _secret_key(secret),
        session_id,
        client_random,
    )
    app_reader = TLSAppDataReader(reader)
    app_writer = TLSAppDataWriter(writer)
    await _check_obfuscated_mtproto_connection(
        app_reader,
        app_writer,
        secret,
        timeout,
        dc_id=dc_id,
        protocol=protocol,
        encoder=encoder,
        decoder=decoder,
    )


async def _read_exactly(
    reader: asyncio.StreamReader,
    size: int,
    timeout: float,
) -> bytes:
    return await asyncio.wait_for(reader.readexactly(size), timeout=timeout)


async def _read_at_least(
    reader: asyncio.StreamReader,
    size: int,
    timeout: float,
) -> bytes:
    data = await asyncio.wait_for(reader.read(size), timeout=timeout)
    if len(data) < size:
        raise ConnectionResetError("connection closed before enough data was read")
    return data


async def _check_socks5(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target: ProxyTarget,
    timeout: float,
    dc_host: str = TELEGRAM_DC_HOST,
    dc_port: int = TELEGRAM_DC_PORT,
) -> None:
    if target.username or target.password:
        writer.write(b"\x05\x01\x02")
    else:
        writer.write(b"\x05\x01\x00")
    await asyncio.wait_for(writer.drain(), timeout=timeout)

    version, method = await _read_exactly(reader, 2, timeout)
    if version != 5:
        raise ConnectionError(f"unexpected SOCKS version: {version}")
    if method == 0xFF:
        raise PermissionError("SOCKS5 auth method rejected")

    if method == 0x02:
        username = (target.username or "").encode("utf-8")
        password = (target.password or "").encode("utf-8")
        if len(username) > 255 or len(password) > 255:
            raise ValueError("SOCKS5 username/password is too long")

        writer.write(
            b"\x01"
            + bytes([len(username)])
            + username
            + bytes([len(password)])
            + password
        )
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        auth_version, status = await _read_exactly(reader, 2, timeout)
        if auth_version != 1 or status != 0:
            raise PermissionError("SOCKS5 username/password rejected")
    elif method != 0x00:
        raise PermissionError(f"unsupported SOCKS5 auth method: {method}")

    host_bytes = bytes(int(part) for part in dc_host.split("."))
    writer.write(b"\x05\x01\x00\x01" + host_bytes + dc_port.to_bytes(2, "big"))
    await asyncio.wait_for(writer.drain(), timeout=timeout)
    response = await _read_exactly(reader, 4, timeout)
    if response[0] != 5 or response[1] != 0:
        raise ConnectionError(f"SOCKS5 CONNECT rejected with code {response[1]}")

    address_type = response[3]
    if address_type == 1:
        await _read_exactly(reader, 4 + 2, timeout)
    elif address_type == 3:
        domain_length = (await _read_exactly(reader, 1, timeout))[0]
        await _read_exactly(reader, domain_length + 2, timeout)
    elif address_type == 4:
        await _read_exactly(reader, 16 + 2, timeout)
    else:
        raise ConnectionError(f"unexpected SOCKS5 address type: {address_type}")

    await _check_direct_mtproto_req_pq(reader, writer, timeout)


async def _check_socks5_target(target: ProxyTarget, timeout: float) -> None:
    errors: list[str] = []
    for dc_host, dc_port in TELEGRAM_DCS:
        reader = None
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.server, target.port),
                timeout=timeout,
            )
            await _check_socks5(
                reader,
                writer,
                target,
                timeout,
                dc_host=dc_host,
                dc_port=dc_port,
            )
            return
        except Exception as exc:
            errors.append(f"{dc_host}:{dc_port}: {type(exc).__name__}")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    raise ConnectionError("; ".join(errors[-5:]) or "SOCKS5 Telegram req_pq_multi failed")


async def _check_direct_mtproto_req_pq(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
) -> None:
    errors: list[str] = []
    transports = [
        ("intermediate", MTTRANSPORT_INTERMEDIATE, _encode_intermediate_packet, _read_direct_intermediate_packet),
        ("abridged", b"\xef", _encode_abridged_packet, _read_direct_abridged_packet),
    ]

    # A SOCKS CONNECT gives us one tunnel, so use the most common direct
    # MTProto transport first. If it fails the proxy is very unlikely to be
    # usable by Telegram for this DC.
    transport_name, tag, encoder, decoder = transports[0]
    try:
        nonce = os.urandom(16)
        writer.write(tag)
        writer.write(encoder(_make_unencrypted_mtproto_message(_make_req_pq_multi_body(nonce))))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        response = await decoder(reader, timeout)
        _validate_res_pq(response, nonce)
        return
    except Exception as exc:
        errors.append(f"{transport_name}: {type(exc).__name__}")
        raise ConnectionError("; ".join(errors)) from exc


async def _read_direct_intermediate_packet(
    reader: asyncio.StreamReader,
    timeout: float,
) -> bytes:
    length = int.from_bytes(await _read_exactly(reader, 4, timeout), "little")
    if length <= 0 or length > 1_048_576:
        raise ConnectionError(f"invalid direct MTProto packet length: {length}")
    return await _read_exactly(reader, length, timeout)


async def _read_direct_abridged_packet(
    reader: asyncio.StreamReader,
    timeout: float,
) -> bytes:
    first = (await _read_exactly(reader, 1, timeout))[0]
    if first < 127:
        length_words = first
    else:
        length_words = int.from_bytes(await _read_exactly(reader, 3, timeout), "little")
    length = length_words * 4
    if length <= 0 or length > 1_048_576:
        raise ConnectionError(f"invalid direct abridged MTProto packet length: {length}")
    return await _read_exactly(reader, length, timeout)


async def check_many(
    proxy_urls: Iterable[str],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    attempts: int = DEFAULT_ATTEMPTS,
    min_successes: int = DEFAULT_MIN_SUCCESSES,
) -> list[CheckResult]:
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def run_one(proxy_url: str) -> CheckResult:
        async with semaphore:
            return await check_proxy(
                proxy_url,
                timeout=timeout,
                attempts=attempts,
                min_successes=min_successes,
            )

    tasks = [run_one(proxy_url) for proxy_url in proxy_urls if proxy_url.strip()]
    if not tasks:
        return []
    return await asyncio.gather(*tasks)


def read_proxy_urls(paths: list[Path], inline_urls: list[str]) -> list[str]:
    urls: list[str] = []
    urls.extend(inline_urls)

    for path in paths:
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                clean = line.strip()
                if clean and not clean.startswith("#"):
                    urls.append(clean)

    return urls


def print_human_result(result: CheckResult) -> None:
    attempt_suffix = ""
    if result.attempts > 1 or result.successes > 1:
        attempt_suffix = f" ({result.successes}/{result.attempts})"

    if result.status == ProxyStatus.LIVE:
        print(f"[LIVE] {result.server}:{result.port} {result.latency_ms:.1f} ms{attempt_suffix}")
        return

    if result.status == ProxyStatus.INVALID:
        print(f"[INVALID] {result.url} ({result.error})")
        return

    print(f"[DEAD] {result.server}:{result.port} ({result.error}){attempt_suffix}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fast async checker for Telegram MTProto proxy links and host:port targets.",
    )
    parser.add_argument("urls", nargs="*", help="Proxy URLs or host:port targets.")
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        type=Path,
        default=[],
        help="Read proxy URLs from a text file. Can be used multiple times.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds. Default: {DEFAULT_TIMEOUT}.",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Maximum concurrent checks. Default: {DEFAULT_CONCURRENCY}.",
    )
    parser.add_argument(
        "-a",
        "--attempts",
        type=int,
        default=DEFAULT_ATTEMPTS,
        help=f"Probe attempts per proxy. Default: {DEFAULT_ATTEMPTS}.",
    )
    parser.add_argument(
        "--min-successes",
        type=int,
        default=DEFAULT_MIN_SUCCESSES,
        help=f"Successful attempts required to mark LIVE. Default: {DEFAULT_MIN_SUCCESSES}.",
    )
    parser.add_argument("--json", action="store_true", help="Print results as JSON.")
    parser.add_argument(
        "--info",
        action="store_true",
        help="Include proxy metadata: secret mode/domain, sponsor hints, and ipwho.is data.",
    )
    parser.add_argument(
        "--no-ipwhois",
        action="store_true",
        help="Do not call ipwho.is when --info is enabled.",
    )
    parser.add_argument(
        "--alive-only",
        action="store_true",
        help="Print only live proxies in human-readable mode.",
    )
    return parser


async def async_main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    urls = read_proxy_urls(args.file, args.urls)
    if not urls:
        parser.error("provide at least one URL or --file")

    results = await check_many(
        urls,
        timeout=args.timeout,
        concurrency=args.concurrency,
        attempts=args.attempts,
        min_successes=args.min_successes,
    )

    info_by_url = {}
    if args.info:
        from .info import collect_proxy_info

        for url in urls:
            try:
                info_by_url[url.strip()] = collect_proxy_info(
                    url,
                    include_ipwhois=not args.no_ipwhois,
                    timeout=args.timeout,
                )
            except Exception as exc:
                info_by_url[url.strip()] = {"error": str(exc)}

    if args.json:
        payload = []
        for result in results:
            item = asdict(result)
            if args.info:
                item["info"] = info_by_url.get(result.url)
            payload.append(item)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for result in results:
            if args.alive_only and not result.alive:
                continue
            print_human_result(result)
            if args.info:
                print_human_info(info_by_url.get(result.url) or {})

        alive_count = sum(result.alive for result in results)
        print(f"\nSummary: {alive_count}/{len(results)} live")

    return 0 if any(result.alive for result in results) else 1


def main() -> int:
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


def print_human_info(info: dict) -> None:
    if not info:
        return
    if error := info.get("error"):
        print(f"  info: {error}")
        return

    secret = info.get("secret") or {}
    sponsor = info.get("sponsor") or {}
    ipwhois = info.get("ipwhois") or {}

    mode = secret.get("mode") or "none"
    domain = secret.get("domain") or secret.get("embedded_text") or "-"
    print(f"  secret: mode={mode}, domain={domain}")

    sponsor_state = sponsor.get("detected")
    if sponsor_state is True:
        label = f"likely yes ({sponsor.get('confidence')})"
    elif sponsor_state is False:
        label = f"likely no ({sponsor.get('confidence')})"
    else:
        label = "unknown"
    print(f"  sponsor: {label}")
    for evidence in sponsor.get("evidence") or []:
        print(f"    - {evidence}")

    if ipwhois:
        if ipwhois.get("ok"):
            location = ", ".join(
                part for part in (ipwhois.get("country"), ipwhois.get("city")) if part
            )
            org = ipwhois.get("org") or ipwhois.get("isp") or "-"
            print(f"  ipwho.is: {ipwhois.get('ip')} {location} AS{ipwhois.get('asn')} {org}")
        else:
            print(f"  ipwho.is: {ipwhois.get('error')}")


if __name__ == "__main__":
    raise SystemExit(main())
