from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from dataclasses import asdict
from typing import Any

from .models import ProxyTarget
from .parser import _decode_secret, _secret_key, _secret_mode, _secret_sni, parse_proxy_url


def collect_proxy_info(
    proxy_url: str,
    *,
    include_ipwhois: bool = True,
    timeout: float = 5.0,
) -> dict[str, Any]:
    target = parse_proxy_url(proxy_url)
    info: dict[str, Any] = {
        "target": asdict(target),
        "canonical": _canonical_url(target),
        "secret": _secret_info(target),
    }

    if include_ipwhois:
        info["ipwhois"] = _ipwhois(target.server, timeout=timeout)

    return info


def _canonical_url(target: ProxyTarget) -> str:
    if target.kind == "socks5":
        query = {
            "server": target.server,
            "port": str(target.port),
        }
        if target.username:
            query["user"] = target.username
        if target.password:
            query["pass"] = target.password
        return "tg://socks?" + urllib.parse.urlencode(query)

    if target.kind == "mtproto":
        return "tg://proxy?" + urllib.parse.urlencode(
            {
                "server": target.server,
                "port": str(target.port),
                "secret": target.secret or "",
            }
        )

    return f"{target.server}:{target.port}"


def _secret_info(target: ProxyTarget) -> dict[str, Any]:
    if target.kind != "mtproto":
        return {"present": False}

    try:
        secret = _decode_secret(target.secret)
        mode = _secret_mode(secret)
        key = _secret_key(secret)
    except Exception as exc:
        return {
            "present": bool(target.secret),
            "valid": False,
            "error": str(exc),
        }

    domain = _secret_sni(secret) if mode == "fake_tls" else None
    embedded_tail = secret[17:] if len(secret) > 17 else b""
    embedded_text = None
    if embedded_tail:
        try:
            embedded_text = embedded_tail.decode("utf-8")
        except UnicodeDecodeError:
            embedded_text = embedded_tail.decode("utf-8", errors="replace")

    return {
        "present": True,
        "valid": True,
        "mode": mode,
        "raw": target.secret,
        "bytes_len": len(secret),
        "key_hex": key.hex(),
        "domain": domain,
        "embedded_text": embedded_text,
        "hex": secret.hex(),
    }


def _ipwhois(host: str, *, timeout: float) -> dict[str, Any]:
    try:
        ip = socket.gethostbyname(host)
    except OSError as exc:
        return {"ok": False, "host": host, "error": f"resolve failed: {exc}"}

    url = f"https://ipwho.is/{urllib.parse.quote(ip)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"ok": False, "host": host, "ip": ip, "error": str(exc)}

    return {
        "ok": bool(payload.get("success", True)),
        "host": host,
        "ip": ip,
        "type": payload.get("type"),
        "continent": payload.get("continent"),
        "country": payload.get("country"),
        "country_code": payload.get("country_code"),
        "region": payload.get("region"),
        "city": payload.get("city"),
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
        "asn": (payload.get("connection") or {}).get("asn"),
        "org": (payload.get("connection") or {}).get("org"),
        "isp": (payload.get("connection") or {}).get("isp"),
        "domain": (payload.get("connection") or {}).get("domain"),
        "timezone": (payload.get("timezone") or {}).get("id"),
    }
