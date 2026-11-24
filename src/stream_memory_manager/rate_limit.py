"""Account-level persistent rate-limit scheduler, bounded backoff, and request budget governance."""

from __future__ import annotations

import asyncio
import random
import re
from dataclasses import dataclass
from typing import Any

from stream_memory_manager.clock import Clock, SystemClock
from stream_memory_manager.db import Database
from stream_memory_manager.models import (
    ErrorClass,
    ExitCode,
    RequestBudget,
    StreamMemoryError,
    utc_now_iso,
)

RETRY_AFTER_TEXT_RE = re.compile(
    r"(?i)(?:wait|retry\s+(?:after|in)|try\s+again\s+in)\s+(\d+(?:\.\d+)?)\s*(?:s|sec|secs|second|seconds)\b"
)


def parse_retry_after_seconds(
    *,
    header_value: str | None = None,
    error_message: str | None = None,
) -> float | None:
    """Extract server-directed wait duration from HTTP Retry-After or structured error text."""
    if header_value is not None:
        raw = header_value.strip()
        try:
            val = float(raw)
            if val >= 0:
                return val
        except ValueError:
            pass
    if error_message:
        m = RETRY_AFTER_TEXT_RE.search(error_message)
        if m:
            try:
                val = float(m.group(1))
                if val >= 0:
                    return val
            except ValueError:
                pass
    return None


@dataclass
class BackoffPolicy:
    base_seconds: float = 2.0
    max_seconds: float = 60.0
    jitter_ratio: float = 0.2

    def compute_delay(
        self,
        attempt: int,
        *,
        server_retry_after: float | None = None,
        rng: random.Random | None = None,
    ) -> float:
        """Compute bounded exponential backoff while NEVER shortening an explicit server Retry-After."""
        exp_delay = float(min(self.max_seconds, self.base_seconds * (2 ** max(0, attempt - 1))))
        gen = rng or random.Random()  # noqa: S311  # nosec B311
        jitter = exp_delay * self.jitter_ratio * gen.uniform(0.0, 1.0)
        computed = float(min(self.max_seconds, exp_delay + jitter))
        if server_retry_after is not None:
            # Never shorten explicit server-directed wait interval (Section 18)
            return float(max(server_retry_after, computed))
        return computed


class BudgetTracker:
    """Enforces bounded request expenditure per execution run (Invariant 15)."""

    def __init__(self, budget: RequestBudget) -> None:
        self.budget = budget
        self.writes_attempted = 0
        self.verification_requests = 0
        self.reconciliation_requests = 0
        self.total_retries = 0
        self.consecutive_errors = 0
        self.unresolved_operations = 0

    def consume_write(self) -> None:
        if self.writes_attempted >= self.budget.max_planned_writes:
            raise StreamMemoryError(
                f"Write request budget exhausted ({self.writes_attempted}/{self.budget.max_planned_writes})",
                error_class=ErrorClass.RATE_LIMIT_ERROR,
                exit_code=ExitCode.TEMPORARY_FAILURE,
            )
        self.writes_attempted += 1

    def consume_reconciliation(self) -> None:
        if self.reconciliation_requests >= self.budget.max_reconciliation_requests:
            raise StreamMemoryError(
                f"Reconciliation request budget exhausted ({self.reconciliation_requests}/{self.budget.max_reconciliation_requests})",
                error_class=ErrorClass.RATE_LIMIT_ERROR,
                exit_code=ExitCode.TEMPORARY_FAILURE,
            )
        self.reconciliation_requests += 1

    def record_success(self) -> None:
        self.consecutive_errors = 0

    def record_error(self) -> bool:
        """Increment consecutive errors; return True if threshold exceeded and run must pause."""
        self.consecutive_errors += 1
        return self.consecutive_errors >= self.budget.max_consecutive_errors

    def snapshot(self) -> dict[str, int]:
        return {
            "writes_attempted": self.writes_attempted,
            "max_planned_writes": self.budget.max_planned_writes,
            "verification_requests": self.verification_requests,
            "reconciliation_requests": self.reconciliation_requests,
            "max_reconciliation_requests": self.budget.max_reconciliation_requests,
            "total_retries": self.total_retries,
            "consecutive_errors": self.consecutive_errors,
            "max_consecutive_errors": self.budget.max_consecutive_errors,
            "unresolved_operations": self.unresolved_operations,
        }


class AccountRateScheduler:
    """Single shared account-level scheduler across all governed MCP requests.

    - Default conservative 2.0s minimum interval (half of Sandbar's documented 1 req/s).
    - Zero reliance on burst allowance.
    - At most 1 mutating request in flight via an exclusive asyncio.Lock.
    - Persists `next_allowed_epoch_ms` in SQLite so process restarts cannot burst.
    - Uses monotonic clock in-process so wall-clock jumps backwards cannot defeat pacing.
    """

    def __init__(
        self,
        db: Database,
        account_key: str,
        *,
        min_interval_seconds: float = 2.0,
        max_consecutive_429s: int = 3,
        clock: Clock | None = None,
        backoff: BackoffPolicy | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.db = db
        self.account_key = account_key
        self.min_interval_seconds = max(0.0, min_interval_seconds)
        self.max_consecutive_429s = max(1, max_consecutive_429s)
        self.clock: Clock = clock or SystemClock()
        self.backoff = backoff or BackoffPolicy()
        self.rng = rng or random.Random()  # noqa: S311
        self._schedule_lock = asyncio.Lock()
        self._mutation_lock = asyncio.Lock()
        self._next_allowed_monotonic: float = 0.0
        self._load_persisted_floor()

    def _load_persisted_floor(self) -> None:
        row = self.db.conn.execute(
            "SELECT next_allowed_epoch_ms FROM rate_limit_state WHERE account_key = ?;",
            (self.account_key,),
        ).fetchone()
        if not row:
            return
        persisted_epoch_s = int(row["next_allowed_epoch_ms"]) / 1000.0
        now_epoch = self.clock.now_epoch()
        remaining = persisted_epoch_s - now_epoch
        # Clamp extreme future clock-jump artifacts to 1 hour (NEVER drop >3600s cooldowns to 0!)
        if remaining > 0:
            clamped = min(remaining, 3600.0)
            self._next_allowed_monotonic = max(
                self._next_allowed_monotonic, self.clock.monotonic() + clamped
            )

    def _persist_state(
        self,
        *,
        wait_until_delta_s: float,
        consecutive_429s: int | None = None,
        last_retry_after_s: float | None = None,
        increment_requests: bool = False,
    ) -> None:
        now_epoch = self.clock.now_epoch()
        next_epoch_ms = int((now_epoch + max(0.0, wait_until_delta_s)) * 1000)
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM rate_limit_state WHERE account_key = ?;", (self.account_key,)
            ).fetchone()
            cur_429 = int(row["consecutive_429s"]) if row else 0
            cur_total = int(row["total_requests"]) if row else 0
            cur_ra = row["last_retry_after_s"] if row else None
            new_429 = cur_429 if consecutive_429s is None else consecutive_429s
            new_total = cur_total + (1 if increment_requests else 0)
            new_ra = cur_ra if last_retry_after_s is None else last_retry_after_s
            conn.execute(
                """
                INSERT INTO rate_limit_state (
                    account_key, next_allowed_epoch_ms, consecutive_429s,
                    last_retry_after_s, total_requests, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_key) DO UPDATE SET
                    next_allowed_epoch_ms = MAX(rate_limit_state.next_allowed_epoch_ms, excluded.next_allowed_epoch_ms),
                    consecutive_429s = excluded.consecutive_429s,
                    last_retry_after_s = excluded.last_retry_after_s,
                    total_requests = excluded.total_requests,
                    updated_at = excluded.updated_at;
                """,
                (self.account_key, next_epoch_ms, new_429, new_ra, new_total, utc_now_iso()),
            )

    async def acquire_slot(self, *, governed: bool = True) -> float:
        """Wait until the next safe request slot and reserve the subsequent interval."""
        if not governed:
            return 0.0
        async with self._schedule_lock:
            now_mono = self.clock.monotonic()
            # Also re-check persisted floor in case another process updated it
            row = self.db.conn.execute(
                "SELECT next_allowed_epoch_ms FROM rate_limit_state WHERE account_key = ?;",
                (self.account_key,),
            ).fetchone()
            if row:
                persisted_remaining = (
                    int(row["next_allowed_epoch_ms"]) / 1000.0
                ) - self.clock.now_epoch()
                if persisted_remaining > 0:
                    self._next_allowed_monotonic = max(
                        self._next_allowed_monotonic, now_mono + min(persisted_remaining, 3600.0)
                    )

            wait_s = max(0.0, self._next_allowed_monotonic - now_mono)
            if wait_s > 0:
                await self.clock.sleep(wait_s)

            # Reserve the interval starting from post-sleep monotonic time
            after_mono = self.clock.monotonic()
            self._next_allowed_monotonic = after_mono + self.min_interval_seconds
            self._persist_state(
                wait_until_delta_s=self.min_interval_seconds,
                increment_requests=True,
            )
            return wait_s

    @property
    def mutation_lock(self) -> asyncio.Lock:
        """Exclusive lock ensuring at most one mutating request in flight at a time."""
        return self._mutation_lock

    def record_success(self) -> None:
        self._persist_state(wait_until_delta_s=0.0, consecutive_429s=0)

    def record_rate_limit(self, *, retry_after_seconds: float | None = None) -> tuple[float, bool]:
        """Record a rate-limit response, push back schedule, and report (delay_s, should_pause)."""
        row = self.db.conn.execute(
            "SELECT consecutive_429s FROM rate_limit_state WHERE account_key = ?;",
            (self.account_key,),
        ).fetchone()
        new_429 = (int(row["consecutive_429s"]) if row else 0) + 1
        delay = self.backoff.compute_delay(
            new_429, server_retry_after=retry_after_seconds, rng=self.rng
        )
        # Never shorten server-directed Retry-After and never go below min_interval
        effective_delay = max(delay, self.min_interval_seconds)
        if retry_after_seconds is not None:
            effective_delay = max(effective_delay, retry_after_seconds)
        self._next_allowed_monotonic = max(
            self._next_allowed_monotonic, self.clock.monotonic() + effective_delay
        )
        self._persist_state(
            wait_until_delta_s=effective_delay,
            consecutive_429s=new_429,
            last_retry_after_s=retry_after_seconds,
        )
        should_pause = new_429 >= self.max_consecutive_429s
        return effective_delay, should_pause

    def status_snapshot(self) -> dict[str, Any]:
        row = self.db.conn.execute(
            "SELECT * FROM rate_limit_state WHERE account_key = ?;",
            (self.account_key,),
        ).fetchone()
        remaining = max(0.0, self._next_allowed_monotonic - self.clock.monotonic())
        return {
            "account_key": self.account_key,
            "min_interval_seconds": self.min_interval_seconds,
            "cooldown_remaining_seconds": round(remaining, 3),
            "consecutive_429s": int(row["consecutive_429s"]) if row else 0,
            "last_retry_after_s": row["last_retry_after_s"] if row else None,
            "total_requests": int(row["total_requests"]) if row else 0,
        }
