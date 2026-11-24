"""Concurrency, OS flock single-writer exclusion across processes, concurrent readers, and graceful shutdown."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from stream_memory_manager.clock import FakeClock
from stream_memory_manager.compiler import compile_memory
from stream_memory_manager.db import Database
from stream_memory_manager.executor import ExecutionEngine
from stream_memory_manager.locking import AccountWriterLock
from stream_memory_manager.mcp_adapter import SandbarMCPAdapter
from stream_memory_manager.mock_server import RunningMockServer
from stream_memory_manager.models import ExecutionMode, LockContentionError, PlanStatus
from stream_memory_manager.planner import ImportPlanner, observe_remote_state
from stream_memory_manager.rate_limit import AccountRateScheduler
from stream_memory_manager.registry import KnowledgeRegistry
from tests.conftest import seed_synthetic_records


def test_single_writer_lock_blocks_second_handle_and_subprocess(tmp_path: Path) -> None:
    lock_dir = tmp_path / "locks"
    lock1 = AccountWriterLock(lock_dir, "acct_primary")
    lock2 = AccountWriterLock(lock_dir, "acct_primary")

    owner = lock1.acquire()
    assert owner.pid > 0
    assert lock1.is_held

    # Same-process second handle fails closed
    with pytest.raises(LockContentionError):
        lock2.acquire()

    # Real independent subprocess attempting to acquire same account lock MUST fail!
    code = (
        "from pathlib import Path; "
        "from stream_memory_manager.locking import AccountWriterLock; "
        f"l = AccountWriterLock(Path({str(lock_dir)!r}), 'acct_primary'); "
        "l.acquire()"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)  # noqa: S603
    assert proc.returncode != 0
    assert "LockContentionError" in proc.stderr

    # Releasing allows immediate acquisition (and OS kernel releases automatically on SIGKILL)
    lock1.release()
    owner2 = lock2.acquire()
    assert owner2.nonce != owner.nonce
    lock2.release()


def test_concurrent_read_only_access_allowed_while_writer_holds_lock(
    tmp_db: Database, tmp_path: Path
) -> None:
    reg = KnowledgeRegistry(tmp_db)
    seed_synthetic_records(reg, count=2)
    lock = AccountWriterLock(tmp_path / "locks", "acct_primary")
    with lock:
        ro = Database(tmp_db.db_path, read_only=True)
        try:
            ro_reg = KnowledgeRegistry(ro)
            assert len(ro_reg.list_records()) == 2
        finally:
            ro.close()


@pytest.mark.asyncio
async def test_graceful_shutdown_stops_scheduling_and_resumes_cleanly(
    tmp_db: Database,
    tmp_path: Path,
    fake_clock: FakeClock,
    mock_server: RunningMockServer,
) -> None:
    reg = KnowledgeRegistry(tmp_db)
    seed_synthetic_records(reg, count=4)
    compile_memory(reg, include_index=False, include_briefing=False)

    tok = mock_server.state.issue_token("acct_primary")
    sched = AccountRateScheduler(tmp_db, "acct_primary", min_interval_seconds=2.0, clock=fake_clock)
    adapter = SandbarMCPAdapter(
        server_url=mock_server.mcp_url,
        scheduler=sched,
        bearer_token=tok["access_token"],
        allow_localhost_http=True,
    )
    caps = await adapter.discover_capabilities()
    from stream_memory_manager.auth import AccountBindingManager
    from stream_memory_manager.capabilities import CapabilityStore

    CapabilityStore(tmp_db).save_snapshot(caps)
    binding = AccountBindingManager(tmp_db).upsert_binding(
        profile_name="default",
        server_url=mock_server.mcp_url,
        issuer=mock_server.state.base_url,
        account_id="acct_primary",
        account_id_verified=True,
        confirmed_by_user=True,
    )
    remote = await observe_remote_state(adapter)
    planner = ImportPlanner(tmp_db, reg)
    plan = planner.build_plan(
        mode=ExecutionMode.MOCK,
        account_binding_hash=binding["binding_hash"],
        capabilities=caps,
        remote_state=remote,
    )
    planner.approve_plan(plan["plan_id"])

    # Trigger graceful shutdown right after the 2nd operation verifies
    seen_verifies = 0

    def _shutdown_hook(boundary: str, _op_id: str) -> None:
        nonlocal seen_verifies
        if boundary == "after_verification_before_persist":
            seen_verifies += 1
            if seen_verifies >= 2:
                engine.request_shutdown()

    engine = ExecutionEngine(
        db=tmp_db,
        registry=reg,
        adapter=adapter,
        lock_dir=tmp_path / "locks",
        fault_hook=_shutdown_hook,
    )
    rep1 = await engine.execute_plan(plan["plan_id"])
    assert rep1.plan_status == PlanStatus.PAUSED
    assert rep1.paused_reason == "SHUTDOWN_REQUESTED"
    assert rep1.verified_count == 3  # 1 folder + 2 logs verified before shutdown stopped scheduling
    assert rep1.pending_count == 3

    # Resume cleanly without duplicating already-verified Logs
    engine2 = ExecutionEngine(db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks")
    rep2 = await engine2.execute_plan(plan["plan_id"])
    assert rep2.plan_status == PlanStatus.COMPLETED
    assert len(mock_server.state.ground_truth_logs("acct_primary")) == 4
