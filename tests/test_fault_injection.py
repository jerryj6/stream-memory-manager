"""Systematic fault-injection testing across EVERY operation boundary (Section 25.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from stream_memory_manager.auth import AccountBindingManager
from stream_memory_manager.capabilities import CapabilityStore
from stream_memory_manager.clock import FakeClock
from stream_memory_manager.compiler import compile_memory
from stream_memory_manager.db import Database
from stream_memory_manager.executor import ExecutionEngine
from stream_memory_manager.mcp_adapter import SandbarMCPAdapter
from stream_memory_manager.mock_server import (
    FaultRule,
    MockSandbarState,
    MockServerConfig,
    RunningMockServer,
)
from stream_memory_manager.models import ExecutionMode, PlanStatus, RequestBudget
from stream_memory_manager.planner import ImportPlanner, observe_remote_state
from stream_memory_manager.rate_limit import AccountRateScheduler
from stream_memory_manager.registry import KnowledgeRegistry
from tests.conftest import seed_synthetic_records


class SimulatedProcessCrash(BaseException):
    """Simulates abrupt SIGKILL/power-loss termination at an exact execution boundary."""


async def _prepare_approved_plan(
    db: Database,
    srv: RunningMockServer,
    fake_clock: FakeClock,
    *,
    num_records: int = 3,
    batch_size: int = 2,
) -> tuple[KnowledgeRegistry, SandbarMCPAdapter, str]:
    reg = KnowledgeRegistry(db)
    seed_synthetic_records(reg, count=num_records)
    compile_memory(reg, include_index=False, include_briefing=False)
    tok = srv.state.issue_token("acct_primary")
    sched = AccountRateScheduler(db, "acct_primary", min_interval_seconds=2.0, clock=fake_clock)
    adapter = SandbarMCPAdapter(
        server_url=srv.mcp_url,
        scheduler=sched,
        bearer_token=tok["access_token"],
        allow_localhost_http=True,
    )
    caps = await adapter.discover_capabilities()
    CapabilityStore(db).save_snapshot(caps)
    binding = AccountBindingManager(db).upsert_binding(
        profile_name="default",
        server_url=srv.mcp_url,
        issuer=srv.state.base_url,
        account_id="acct_primary",
        account_id_verified=True,
        confirmed_by_user=True,
    )
    remote = await observe_remote_state(adapter)
    planner = ImportPlanner(db, reg)
    plan = planner.build_plan(
        mode=ExecutionMode.MOCK,
        account_binding_hash=binding["binding_hash"],
        capabilities=caps,
        remote_state=remote,
        budget=RequestBudget(batch_size=batch_size),
    )
    planner.approve_plan(plan["plan_id"])
    return reg, adapter, str(plan["plan_id"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crash_boundary",
    [
        "before_journal_persist",
        "after_journal_persist",
        "before_dispatch",
        "after_ack",
        "before_id_persist",
        "during_verification",
        "after_verification_before_persist",
        "between_batches",
    ],
)
async def test_crash_at_every_operation_boundary_recovers_with_zero_duplicates(
    tmp_path: Path,
    crash_boundary: str,
) -> None:
    """Crash at each boundary on the 2nd operation (first CREATE_LOG), reopen DB, reconcile, resume.

    Verifies against independent mock_server ground truth that ZERO duplicate Logs or Folders exist!
    """
    db_path = tmp_path / f"crash_{crash_boundary}.db"
    fake_clock = FakeClock()
    state = MockSandbarState(MockServerConfig())

    with RunningMockServer(state) as srv:
        db1 = Database(db_path)
        reg1, adapter1, plan_id = await _prepare_approved_plan(
            db1, srv, fake_clock, num_records=3, batch_size=2
        )
        crashed = False

        def _crash_once(boundary: str, op_id: str) -> None:
            nonlocal crashed
            if not crashed and boundary == crash_boundary and op_id.endswith(":op0002"):
                crashed = True
                raise SimulatedProcessCrash(f"Simulated crash at {boundary} on {op_id}")

        engine1 = ExecutionEngine(
            db=db1,
            registry=reg1,
            adapter=adapter1,
            lock_dir=tmp_path / "locks",
            fault_hook=_crash_once,
        )
        # Note: between_batches fires on op0003 (start of batch 2), so also match op0003 for that boundary!
        if crash_boundary == "between_batches":

            def _crash_batch(boundary: str, op_id: str) -> None:
                nonlocal crashed
                if not crashed and boundary == "between_batches":
                    crashed = True
                    raise SimulatedProcessCrash(f"Simulated crash at {boundary} on {op_id}")

            engine1.fault_hook = _crash_batch

        with pytest.raises(SimulatedProcessCrash):
            await engine1.execute_plan(plan_id)
        db1.close()

        # Reopen fresh database instance (simulating brand-new OS process after crash)
        db2 = Database(db_path)
        try:
            reg2 = KnowledgeRegistry(db2)
            sched2 = AccountRateScheduler(
                db2, "acct_primary", min_interval_seconds=2.0, clock=fake_clock
            )
            tok = next(iter(srv.state.tokens.keys()))
            adapter2 = SandbarMCPAdapter(
                server_url=srv.mcp_url,
                scheduler=sched2,
                bearer_token=tok,
                allow_localhost_http=True,
            )
            engine2 = ExecutionEngine(
                db=db2, registry=reg2, adapter=adapter2, lock_dir=tmp_path / "locks"
            )
            # Reconcile first (adopts committed writes if crash occurred in-flight/after-ack;
            # blocks if crash occurred strictly before dispatch so nothing was committed!)
            rec_rep = await engine2.reconcile_plan(plan_id)

            if crash_boundary == "before_dispatch":
                # Because REQUEST_IN_FLIGHT was durably persisted right before socket send,
                # crash before socket send truthfully leaves op0002 in BLOCKED (cannot prove non-commit!).
                # ZERO duplicates created!
                assert rec_rep.plan_status == PlanStatus.BLOCKED
                assert len(srv.state.ground_truth_logs("acct_primary")) == 0
            else:
                # For every other boundary, reconcile + resume finishes with EXACTLY 3 Logs & 1 Folder!
                final_rep = await engine2.execute_plan(plan_id)
                assert final_rep.plan_status == PlanStatus.COMPLETED
                assert len(srv.state.ground_truth_folders("acct_primary")) == 1
                assert len(srv.state.ground_truth_logs("acct_primary")) == 3
        finally:
            db2.close()


@pytest.mark.asyncio
async def test_untrusted_server_responses_malformed_wrong_id_and_body_corruption(
    tmp_path: Path,
) -> None:
    """Verify fail-closed detection of malformed JSON, wrong remote ID, and unexpected body rewrite."""
    # 1. Unexpected server body corruption -> CONFLICTED (not silently marked VERIFIED!)
    fake_clock = FakeClock()
    state = MockSandbarState(MockServerConfig(normalization_mode="corrupt_body"))
    with RunningMockServer(state) as srv:
        db = Database(tmp_path / "corrupt_body.db")
        try:
            reg, adapter, plan_id = await _prepare_approved_plan(db, srv, fake_clock, num_records=1)
            engine = ExecutionEngine(
                db=db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
            )
            rep = await engine.execute_plan(plan_id)
            assert rep.plan_status == PlanStatus.BLOCKED
            assert rep.conflicted_count == 1
        finally:
            db.close()

    # 2. Malformed JSON response during create_note -> UNCERTAIN_REMOTE_OUTCOME (no blind retry!)
    state2 = MockSandbarState(MockServerConfig())
    state2.add_fault(FaultRule(tool_name="create_note", fault_type="malformed_json", remaining=1))
    with RunningMockServer(state2) as srv2:
        db2 = Database(tmp_path / "malformed.db")
        try:
            reg2, adapter2, plan_id2 = await _prepare_approved_plan(
                db2, srv2, fake_clock, num_records=1
            )
            engine2 = ExecutionEngine(
                db=db2, registry=reg2, adapter=adapter2, lock_dir=tmp_path / "locks2"
            )
            rep2 = await engine2.execute_plan(plan_id2)
            assert rep2.uncertain_count == 1
            assert rep2.plan_status == PlanStatus.BLOCKED
        finally:
            db2.close()

    # 3. Wrong returned ID on create_note -> verification fallback finds exact normalized match and adopts real ID!
    state3 = MockSandbarState(MockServerConfig())
    state3.add_fault(FaultRule(tool_name="create_note", fault_type="wrong_id", remaining=1))
    with RunningMockServer(state3) as srv3:
        db3 = Database(tmp_path / "wrong_id.db")
        try:
            reg3, adapter3, plan_id3 = await _prepare_approved_plan(
                db3, srv3, fake_clock, num_records=1
            )
            engine3 = ExecutionEngine(
                db=db3, registry=reg3, adapter=adapter3, lock_dir=tmp_path / "locks3"
            )
            rep3 = await engine3.execute_plan(plan_id3)
            assert rep3.plan_status == PlanStatus.COMPLETED
            assert len(srv3.state.ground_truth_logs("acct_primary")) == 1
            real_id = srv3.state.ground_truth_logs("acct_primary")[0]["id"]
            rec = reg3.get_record("syn_core_instructions")
            assert rec is not None and rec["remote_id"] == real_id
        finally:
            db3.close()
