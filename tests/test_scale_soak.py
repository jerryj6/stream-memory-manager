"""Scale and soak tests using hundreds of synthetic records with FakeClock (Section 25.9)."""

from __future__ import annotations

import time
import tracemalloc
from pathlib import Path

import pytest

from stream_memory_manager.capabilities import default_offline_documented_capabilities
from stream_memory_manager.clock import FakeClock
from stream_memory_manager.compiler import compile_memory, load_compiled_artifacts
from stream_memory_manager.db import Database
from stream_memory_manager.executor import OperationJournal
from stream_memory_manager.models import (
    ExecutionMode,
    InclusionDecision,
    MemoryRecordInput,
    OperationState,
    RequestBudget,
)
from stream_memory_manager.planner import ImportPlanner, ObservedRemoteState
from stream_memory_manager.privacy import evaluate_registry_privacy
from stream_memory_manager.rate_limit import AccountRateScheduler
from stream_memory_manager.reconciliation import reconcile_registry
from stream_memory_manager.registry import KnowledgeRegistry


@pytest.mark.slow
@pytest.mark.asyncio
async def test_scale_600_records_compile_plan_journal_recovery_and_scheduler(
    tmp_path: Path,
) -> None:
    """Verify performance, memory usage, DB growth, planning, and recovery on 600 synthetic records."""
    tracemalloc.start()
    t0 = time.monotonic()

    db_path = tmp_path / "scale.db"
    db = Database(db_path)
    try:
        reg = KnowledgeRegistry(db)
        with db.transaction():
            for i in range(600):
                reg.upsert_record(
                    MemoryRecordInput(
                        logical_id=f"scale_rec_{i:04d}",
                        title=f"Synthetic Knowledge Record {i:04d}",
                        category=("ENGINEERING", "RESEARCH", "PERSONAL", "CIVIC", "HARDWARE")[
                            i % 5
                        ],
                        canonical_subject=f"Unique Subject {i:04d}",
                        body=(
                            f"Synthetic self-contained memory record #{i} covering architecture pattern "
                            f"P-{i % 37}, verification discipline, and temporal marker 2026-11-{(i % 20) + 1:02d}."
                        ),
                        search_aliases=[f"alias-{i}", f"pattern-{i % 37}"],
                        inclusion_decision=InclusionDecision.APPROVED,
                    )
                )

        rec_res = reconcile_registry(reg)
        assert rec_res["active_eligible_count"] == 600

        priv_res = evaluate_registry_privacy(reg)
        assert len(priv_res["hard_blocked"]) == 0

        comp = compile_memory(reg, include_index=True, include_briefing=True)
        assert comp["approved_records_compiled"] == 600
        assert comp["max_conservative_words"] <= 900
        arts = load_compiled_artifacts(reg)
        assert len(arts) >= 602

        planner = ImportPlanner(db, reg)
        caps = default_offline_documented_capabilities()
        plan = planner.build_plan(
            mode=ExecutionMode.DRY_RUN,
            account_binding_hash="scale_bind",
            capabilities=caps,
            remote_state=ObservedRemoteState(is_offline_assumption=True),
            budget=RequestBudget(max_planned_writes=800, batch_size=25),
        )
        plan_id = str(plan["plan_id"])
        planner.approve_plan(plan_id)

        # Simulate durable journal transitions + crash recovery across 100 ops + virtual rate scheduler
        journal = OperationJournal(db)
        ops = journal.list_ops(plan_id)
        for op in ops[:100]:
            op_id = str(op["op_id"])
            journal.transition(op_id, OperationState.READY)
            journal.transition(op_id, OperationState.REQUEST_PREPARED)
            journal.transition(op_id, OperationState.REQUEST_IN_FLIGHT, increment_attempt=True)
            if op["sequence_num"] == 100:
                break  # Leave op 100 in-flight to test crash recovery speed!
            journal.transition(
                op_id, OperationState.ACKNOWLEDGED, remote_id=f"rm_{op['sequence_num']}"
            )
            journal.transition(op_id, OperationState.VERIFIED, increment_verification=True)

        recovery = journal.recover_interrupted_in_flight(plan_id)
        assert len(recovery["promoted_uncertain"]) == 1

        fake_clock = FakeClock()
        sched = AccountRateScheduler(db, "scale_acct", min_interval_seconds=2.0, clock=fake_clock)
        for _ in range(100):
            await sched.acquire_slot()
        assert fake_clock.monotonic() - 1000.0 >= 198.0

        elapsed = time.monotonic() - t0
        _cur_mem, peak_mem = tracemalloc.get_traced_memory()
        db_size_mb = db_path.stat().st_size / (1024 * 1024)

        assert elapsed < 30.0
        assert peak_mem < 150 * 1024 * 1024  # < 150 MB peak traced memory
        assert db_size_mb < 25.0
    finally:
        db.close()
        tracemalloc.stop()
