"""Deterministic rate-limiting, Retry-After, restart cooldown, clock-jump, and budget tests."""

from __future__ import annotations

import random

import pytest

from stream_memory_manager.clock import FakeClock
from stream_memory_manager.db import Database
from stream_memory_manager.models import RequestBudget, StreamMemoryError
from stream_memory_manager.rate_limit import (
    AccountRateScheduler,
    BackoffPolicy,
    BudgetTracker,
    parse_retry_after_seconds,
)


@pytest.mark.asyncio
async def test_scheduler_enforces_conservative_interval_and_no_burst(
    tmp_db: Database, fake_clock: FakeClock
) -> None:
    sched = AccountRateScheduler(
        tmp_db, "acct_1", min_interval_seconds=2.0, clock=fake_clock, rng=random.Random(42)
    )
    t0 = fake_clock.monotonic()
    await sched.acquire_slot()
    t1 = fake_clock.monotonic()
    await sched.acquire_slot()
    t2 = fake_clock.monotonic()
    await sched.acquire_slot()
    t3 = fake_clock.monotonic()

    assert t1 == t0
    assert t2 - t1 >= 2.0
    assert t3 - t2 >= 2.0
    assert fake_clock.sleeps == [2.0, 2.0]


@pytest.mark.asyncio
async def test_scheduler_prevents_burst_across_process_restart(
    tmp_db: Database, fake_clock: FakeClock
) -> None:
    sched1 = AccountRateScheduler(
        tmp_db, "acct_restart", min_interval_seconds=2.5, clock=fake_clock
    )
    await sched1.acquire_slot()
    # Process exits immediately and restarts 0.5s later
    fake_clock.advance(0.5)
    sched2 = AccountRateScheduler(
        tmp_db, "acct_restart", min_interval_seconds=2.5, clock=fake_clock
    )
    t_before = fake_clock.monotonic()
    await sched2.acquire_slot()
    t_after = fake_clock.monotonic()
    assert t_after - t_before == pytest.approx(2.0, abs=0.01)


@pytest.mark.asyncio
async def test_scheduler_immune_to_wall_clock_jump_backwards(
    tmp_db: Database, fake_clock: FakeClock
) -> None:
    sched = AccountRateScheduler(tmp_db, "acct_clock", min_interval_seconds=2.0, clock=fake_clock)
    await sched.acquire_slot()
    # System NTP jumps wall clock backwards by 10 seconds mid-run
    fake_clock.jump_wall_clock(-10.0)
    t_before = fake_clock.monotonic()
    await sched.acquire_slot()
    t_after = fake_clock.monotonic()
    # Monotonic clock still enforces >= 2.0s spacing!
    assert t_after - t_before >= 2.0


def test_retry_after_parsing_and_never_shortened() -> None:
    assert parse_retry_after_seconds(header_value="12") == 12.0
    assert (
        parse_retry_after_seconds(
            error_message="Stream is rate limited. Please wait 7.5 seconds before retrying."
        )
        == 7.5
    )
    policy = BackoffPolicy(base_seconds=2.0, max_seconds=30.0, jitter_ratio=0.1)
    # Explicit server Retry-After of 45s MUST NOT be shortened to max_seconds=30s!
    delay = policy.compute_delay(1, server_retry_after=45.0, rng=random.Random(1))
    assert delay >= 45.0


@pytest.mark.asyncio
async def test_repeated_429_triggers_pause_signal(tmp_db: Database, fake_clock: FakeClock) -> None:
    sched = AccountRateScheduler(
        tmp_db,
        "acct_429",
        min_interval_seconds=2.0,
        max_consecutive_429s=3,
        clock=fake_clock,
        rng=random.Random(7),
    )
    d1, p1 = sched.record_rate_limit(retry_after_seconds=3.0)
    assert d1 >= 3.0 and not p1
    d2, p2 = sched.record_rate_limit(retry_after_seconds=4.0)
    assert d2 >= 4.0 and not p2
    d3, p3 = sched.record_rate_limit(retry_after_seconds=5.0)
    assert d3 >= 5.0 and p3 is True


def test_budget_tracker_hard_bounds() -> None:
    bt = BudgetTracker(
        RequestBudget(max_planned_writes=2, max_reconciliation_requests=1, max_consecutive_errors=2)
    )
    bt.consume_write()
    bt.consume_write()
    with pytest.raises(StreamMemoryError, match="Write request budget exhausted"):
        bt.consume_write()
    bt.consume_reconciliation()
    with pytest.raises(StreamMemoryError, match="Reconciliation request budget exhausted"):
        bt.consume_reconciliation()
    assert bt.record_error() is False
    assert bt.record_error() is True
