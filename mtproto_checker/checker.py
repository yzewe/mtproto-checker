from __future__ import annotations

from .cli import async_main, build_parser, main, print_human_info, print_human_result, read_proxy_urls
from .core import check_many, check_proxy
from .models import CheckResult, ProxyStatus, ProxyTarget
from .parser import _decode_secret, _secret_key, _secret_mode, _secret_sni, parse_proxy_url

__all__ = [
    "CheckResult",
    "ProxyStatus",
    "ProxyTarget",
    "async_main",
    "build_parser",
    "check_many",
    "check_proxy",
    "main",
    "parse_proxy_url",
    "print_human_info",
    "print_human_result",
    "read_proxy_urls",
]


if __name__ == "__main__":
    raise SystemExit(main())
