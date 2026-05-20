from __future__ import annotations

import base64
from urllib.parse import parse_qs, unquote, urlparse

from .models import ProxyTarget


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
