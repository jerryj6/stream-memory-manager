"""Injectable monotonic and wall clock abstractions for deterministic testing."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now_epoch(self) -> float:
        """Current wall-clock Unix epoch seconds."""
        ...

    def monotonic(self) -> float:
        """Monotonic seconds for interval measurement immune to wall-clock jumps."""
        ...

    def now_utc(self) -> datetime:
        """Current UTC datetime."""
        ...

    async def sleep(self, seconds: float) -> None:
        """Async sleep for `seconds` (no-op if <= 0)."""
        ...


class SystemClock:
    def now_epoch(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()

    def now_utc(self) -> datetime:
        return datetime.now(UTC)

    async def sleep(self, seconds: float) -> None:
        if seconds > 0:
            await asyncio.sleep(seconds)


class FakeClock:
    """Deterministic virtual clock supporting wall-clock jumps and sleep recording."""

    def __init__(
        self,
        *,
        initial_epoch: float = 1_795_400_000.0,
        initial_monotonic: float = 1000.0,
    ) -> None:
        self._epoch = initial_epoch
        self._monotonic = initial_monotonic
        self.sleeps: list[float] = []

    def now_epoch(self) -> float:
        return self._epoch

    def monotonic(self) -> float:
        return self._monotonic

    def now_utc(self) -> datetime:
        return datetime.fromtimestamp(self._epoch, tz=UTC)

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("Cannot advance monotonic clock backwards; use jump_wall_clock")
        self._epoch += seconds
        self._monotonic += seconds

    def jump_wall_clock(self, delta_seconds: float) -> None:
        """Simulate NTP/DST/manual system clock shift without altering monotonic time."""
        self._epoch += delta_seconds

    async def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.sleeps.append(seconds)
            self.advance(seconds)
