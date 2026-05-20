from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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
