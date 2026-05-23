from __future__ import annotations

import asyncio
import time
from typing import Iterable

from .constants import DEFAULT_ATTEMPTS, DEFAULT_CONCURRENCY, DEFAULT_MIN_SUCCESSES, DEFAULT_TIMEOUT
from .models import CheckResult, ProxyStatus
from .parser import parse_proxy_url
from .probes import _check_target_once

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
    successful_probe: str | None = None

    for attempt_index in range(attempts):
        attempt_started = time.perf_counter()
        try:
            successful_probe = await _check_target_once(target, timeout)
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
                    probe=successful_probe,
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
