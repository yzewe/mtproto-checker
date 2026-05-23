from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .constants import DEFAULT_ATTEMPTS, DEFAULT_CONCURRENCY, DEFAULT_MIN_SUCCESSES, DEFAULT_TIMEOUT
from .core import check_many
from .models import CheckResult, ProxyStatus

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
        probe_suffix = f" via {result.probe}" if result.probe else ""
        print(
            f"[LIVE] {result.server}:{result.port} "
            f"{result.latency_ms:.1f} ms{probe_suffix}{attempt_suffix}"
        )
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
        help="Include proxy metadata: secret mode/domain and ipwho.is data.",
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
    ipwhois = info.get("ipwhois") or {}

    mode = secret.get("mode") or "none"
    domain = secret.get("domain") or secret.get("embedded_text") or "-"
    print(f"  secret: mode={mode}, domain={domain}")

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
