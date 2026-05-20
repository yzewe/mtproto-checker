from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from dataclasses import asdict
from typing import Any

from .checker import ProxyTarget, _decode_secret, _secret_key, _secret_mode, _secret_sni, parse_proxy_url


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
        "sponsor": _sponsor_info(target),
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


def _sponsor_info(target: ProxyTarget) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(target.raw_url)
    params = urllib.parse.parse_qs(parsed.query)

    explicit_keys = ("sponsor", "channel", "title")
    explicit = {
        key: values[0]
        for key in explicit_keys
        if (values := params.get(key))
    }

    secret = _secret_info(target)
    domain = secret.get("domain") or secret.get("embedded_text")

    evidence = []
    confidence = "unknown"
    detected: bool | None = None

    if explicit.get("sponsor") or explicit.get("channel"):
        detected = True
        confidence = "high"
        evidence.append("URL contains sponsor/channel field")
    if explicit.get("title"):
        evidence.append("URL contains title field")

    if domain:
        evidence.append(f"secret embeds domain/SNI: {domain}")
        if _looks_like_ad_domain(str(domain)):
            detected = True
            confidence = "medium" if confidence == "unknown" else confidence
            evidence.append("secret domain looks promotional/ad-related")
        elif detected is None:
            detected = False
            confidence = "low"

    if detected is None:
        evidence.append("public proxy URL does not expose sponsor metadata")

    return {
        "detected": detected,
        "confidence": confidence,
        "explicit_fields": explicit,
        "secret_domain_hint": domain,
        "evidence": evidence,
        "note": (
            "Telegram MTProxy sponsor channel is not reliably encoded in public proxy URLs. "
            "Without a Telegram API session, this is a passive heuristic, not proof."
        ),
    }


def _looks_like_ad_domain(domain: str) -> bool:
    lowered = domain.lower()
    tokens = (
        "ad",
        "ads",
        "sponsor",
        "promo",
        "proxy",
        "mtproxy",
        "mt-proxy",
        "channel",
        "tg",
        "telegram",
    )
    return any(token in lowered for token in tokens)


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
