"""All 15 Mandatory End-to-End Local Scenarios (A through O) against live localhost Mock MCP Server.

Every test exercises the genuine `mcp==2.3.0` Streamable HTTP client over real localhost TCP sockets
and verifies correctness independently via `mock_server.state.ground_truth_*`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from stream_memory_manager.auth import AccountBindingManager
from stream_memory_manager.capabilities import CapabilityStore
from stream_memory_manager.clock import FakeClock
from stream_memory_manager.compiler import compile_memory
from stream_memory_manager.db import Database
from stream_memory_manager.executor import ExecutionEngine
from stream_memory_manager.locking import AccountWriterLock
from stream_memory_manager.mcp_adapter import SandbarMCPAdapter
from stream_memory_manager.mock_server import (
    FaultRule,
    MockSandbarState,
    MockServerConfig,
    RunningMockServer,
)
from stream_memory_manager.models import (
    AccountMismatchError,
    ApprovalRequiredError,
    EvidenceClass,
    ExecutionMode,
    ExitCode,
    InclusionDecision,
    LockContentionError,
    MemoryRecordInput,
    OperationState,
    OperationType,
    PlanStatus,
    PrivacyClassification,
    RequestBudget,
    SchemaDriftError,
    StreamMemoryError,
)
from stream_memory_manager.planner import ImportPlanner, observe_remote_state
from stream_memory_manager.privacy import evaluate_registry_privacy
from stream_memory_manager.rate_limit import AccountRateScheduler
from stream_memory_manager.reconciliation import reconcile_registry
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import canonical_account_scope
from tests.conftest import seed_synthetic_records


async def _setup_env(
    db: Database,
    srv: RunningMockServer,
    fake_clock: FakeClock,
    *,
    account_id: str = "acct_primary",
    num_records: int = 3,
    include_briefing: bool = True,
    include_index: bool = True,
    budget: RequestBudget | None = None,
) -> tuple[KnowledgeRegistry, SandbarMCPAdapter, ImportPlanner, dict[str, object]]:
    reg = KnowledgeRegistry(db)
    seed_synthetic_records(reg, count=num_records)
    compile_memory(reg, include_index=include_index, include_briefing=include_briefing)
    tok = srv.state.issue_token(account_id)
    sched = AccountRateScheduler(db, account_id, min_interval_seconds=2.0, clock=fake_clock)
    adapter = SandbarMCPAdapter(
        server_url=srv.mcp_url,
        scheduler=sched,
        bearer_token=tok["access_token"],
        allow_localhost_http=True,
    )
    caps = await adapter.discover_capabilities()
    CapabilityStore(db).save_snapshot(caps)
    remote = await observe_remote_state(adapter)
    binding = AccountBindingManager(db).upsert_binding(
        profile_name="default",
        server_url=srv.mcp_url,
        issuer=srv.state.base_url,
        account_id=account_id,
        account_id_verified=True,
        target_folder_id=(
            remote.memory_folder_matches[0].folder_id
            if len(remote.memory_folder_matches) == 1
            else None
        ),
        confirmed_by_user=True,
    )
    planner = ImportPlanner(db, reg)
    plan = planner.build_plan(
        mode=ExecutionMode.MOCK,
        account_binding_hash=binding["binding_hash"],
        capabilities=caps,
        remote_state=remote,
        include_briefing=include_briefing,
        budget=budget,
    )
    return reg, adapter, planner, plan


@pytest.mark.asyncio
async def test_scenario_a_and_b_fresh_import_and_identical_repeat_zero_duplicates(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario A (Fresh import) + Scenario B (Identical repeated import -> zero duplicate writes)."""
    state = MockSandbarState(MockServerConfig(normalization_mode="crlf"))
    with RunningMockServer(state) as srv:
        reg, adapter, planner, plan = await _setup_env(tmp_db, srv, fake_clock, num_records=3)
        plan_id = str(plan["plan_id"])

        # Unapproved plan MUST be refused (Invariant 1)
        engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
        )
        with pytest.raises(ApprovalRequiredError):
            await engine.execute_plan(plan_id)
        assert len(srv.state.ground_truth_logs("acct_primary")) == 0

        # Approve & execute Scenario A
        planner.approve_plan(plan_id, actor="tester", note="Scenario A")
        rep = await engine.execute_plan(plan_id)
        assert rep.plan_status == PlanStatus.COMPLETED
        assert rep.exit_code == ExitCode.SUCCESS

        # Ground-truth check: exactly 1 Memory folder, 3 domain logs + 1 index log = 4 logs, briefing applied!
        gt_folders = srv.state.ground_truth_folders("acct_primary")
        gt_logs = srv.state.ground_truth_logs("acct_primary")
        assert len(gt_folders) == 1
        assert gt_folders[0]["name"] == "Memory"
        assert gt_folders[0]["instruction"] is not None
        assert len(gt_logs) == 4
        assert srv.state.accounts["acct_primary"].briefing is not None

        # Scenario B: Re-compile & build a new plan from unchanged canonical data -> ZERO mutating ops!
        compile_memory(reg, include_index=True, include_briefing=True)
        remote2 = await observe_remote_state(adapter)
        assert adapter.capabilities is not None
        plan2 = planner.build_plan(
            mode=ExecutionMode.MOCK,
            account_binding_hash=str(plan["account_binding_hash"]),
            capabilities=adapter.capabilities,
            remote_state=remote2,
            include_briefing=True,
        )
        assert plan2["summary"]["mutating_operations"] == 0
        assert plan2["summary"]["skipped_unchanged"] == 4
        planner.approve_plan(str(plan2["plan_id"]))
        rep2 = await engine.execute_plan(str(plan2["plan_id"]))
        assert rep2.plan_status == PlanStatus.COMPLETED
        assert len(srv.state.ground_truth_logs("acct_primary")) == 4  # Zero duplicates!


@pytest.mark.asyncio
async def test_scenario_c_interrupted_import_and_safe_resume(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario C: Interrupt halfway through (via 429 rate-limit pause), restart & resume without duplicates."""
    state = MockSandbarState(MockServerConfig())
    with RunningMockServer(state) as srv:
        reg, adapter, planner, plan = await _setup_env(
            tmp_db,
            srv,
            fake_clock,
            num_records=4,
            include_index=False,
            include_briefing=False,
            budget=RequestBudget(max_retries_per_op=0),
        )
        plan_id = str(plan["plan_id"])
        planner.approve_plan(plan_id)

        # Inject a 429 after 2 successful creates so execution pauses cleanly mid-plan
        ops_done = 0

        def _inject_midway(boundary: str, _op_id: str) -> None:
            nonlocal ops_done
            if boundary == "after_verification_before_persist":
                ops_done += 1
                if ops_done == 2:  # 2 logs verified -> trigger rate limit on 3rd log
                    srv.state.add_fault(
                        FaultRule(
                            tool_name="create_note",
                            fault_type="http_429",
                            remaining=1,
                            retry_after_s=2.0,
                        )
                    )

        engine = ExecutionEngine(
            db=tmp_db,
            registry=reg,
            adapter=adapter,
            lock_dir=tmp_path / "locks",
            fault_hook=_inject_midway,
        )
        rep1 = await engine.execute_plan(plan_id)
        assert rep1.plan_status == PlanStatus.PAUSED
        assert rep1.paused_reason == "RATE_LIMITED"
        assert len(srv.state.ground_truth_logs("acct_primary")) == 2

        # Resume on a fresh engine instance -> remaining 2 logs created, zero duplicates!
        engine2 = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
        )
        rep2 = await engine2.execute_plan(plan_id)
        assert rep2.plan_status == PlanStatus.COMPLETED
        assert len(srv.state.ground_truth_logs("acct_primary")) == 4


@pytest.mark.asyncio
async def test_scenario_d_commit_without_acknowledgment_reconciles_with_zero_duplicates(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """MANDATORY Scenario D: Server commits Log then drops TCP connection before ack -> reconcile adopts!"""
    state = MockSandbarState(MockServerConfig())
    state.add_fault(FaultRule(tool_name="create_note", fault_type="commit_then_drop", remaining=1))
    with RunningMockServer(state) as srv:
        reg, adapter, planner, plan = await _setup_env(
            tmp_db, srv, fake_clock, num_records=2, include_index=False, include_briefing=False
        )
        plan_id = str(plan["plan_id"])
        planner.approve_plan(plan_id)

        engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
        )
        rep1 = await engine.execute_plan(plan_id)
        assert rep1.plan_status == PlanStatus.BLOCKED
        assert rep1.exit_code == ExitCode.AMBIGUOUS_REMOTE_OUTCOME
        assert rep1.uncertain_count == 1
        # Ground truth already has the committed Log!
        assert len(srv.state.ground_truth_logs("acct_primary")) == 1

        # Calling execute_plan directly while UNCERTAIN exists MUST refuse to write!
        rep_refused = await engine.execute_plan(plan_id)
        assert rep_refused.uncertain_count == 1
        assert len(srv.state.ground_truth_logs("acct_primary")) == 1

        # Reconcile adopts the committed Log via exact normalized hash -> ZERO duplicate created!
        rec_rep = await engine.reconcile_plan(plan_id)
        assert rec_rep.uncertain_count == 0
        assert len(srv.state.ground_truth_logs("acct_primary")) == 1

        # Resume completes the 2nd Log cleanly!
        final_rep = await engine.execute_plan(plan_id)
        assert final_rep.plan_status == PlanStatus.COMPLETED
        assert len(srv.state.ground_truth_logs("acct_primary")) == 2


@pytest.mark.asyncio
async def test_scenario_e_unresolvable_ambiguous_outcome_blocks_instead_of_duplicating(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario E: Server commits write, drops response, AND suppresses all read/search evidence -> MUST BLOCK!"""
    state = MockSandbarState(MockServerConfig())
    state.add_fault(
        FaultRule(tool_name="create_note", fault_type="commit_and_suppress_evidence", remaining=1)
    )
    with RunningMockServer(state) as srv:
        reg, adapter, planner, plan = await _setup_env(
            tmp_db,
            srv,
            fake_clock,
            num_records=1,
            include_index=False,
            include_briefing=False,
            budget=RequestBudget(max_verification_attempts_per_op=2),
        )
        plan_id = str(plan["plan_id"])
        planner.approve_plan(plan_id)

        engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
        )
        rep1 = await engine.execute_plan(plan_id)
        assert rep1.uncertain_count == 1
        assert len(srv.state.ground_truth_logs("acct_primary")) == 1

        rec_rep = await engine.reconcile_plan(plan_id)
        assert rec_rep.plan_status == PlanStatus.BLOCKED
        assert rec_rep.blocked_count == 1
        # CRITICAL: Must STILL have only 1 ground-truth Log (never blindly retried!)
        assert len(srv.state.ground_truth_logs("acct_primary")) == 1


@pytest.mark.asyncio
async def test_scenario_f_delayed_indexing_waits_without_resending_create(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario F: Search/read visibility lags behind create_note -> bounded verification waits, zero duplicates."""
    state = MockSandbarState(MockServerConfig(default_index_delay_reads=2))
    with RunningMockServer(state) as srv:
        reg, adapter, planner, plan = await _setup_env(
            tmp_db,
            srv,
            fake_clock,
            num_records=2,
            include_index=False,
            include_briefing=False,
            budget=RequestBudget(max_verification_attempts_per_op=4),
        )
        plan_id = str(plan["plan_id"])
        planner.approve_plan(plan_id)

        engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
        )
        rep = await engine.execute_plan(plan_id)
        assert rep.plan_status == PlanStatus.COMPLETED
        assert len(srv.state.ground_truth_logs("acct_primary")) == 2
        # Audit R20: Verify multi-attempt delayed verification actually polled & slept (not single-shot pass!)
        ops = engine.journal.list_ops(plan_id)
        create_ops = [o for o in ops if o["op_type"] == "CREATE_LOG"]
        assert all(int(o["verification_attempts"]) >= 2 for o in create_ops)
        assert len(fake_clock.sleeps) > 0


@pytest.mark.asyncio
async def test_scenario_g_and_h_expired_auth_pause_wrong_account_block_and_valid_resume(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario G (Expired auth -> durable pause -> renew -> resume) + Scenario H (Wrong account -> refuse!)."""
    state = MockSandbarState(MockServerConfig())
    with RunningMockServer(state) as srv:
        reg, adapter, planner, plan = await _setup_env(
            tmp_db, srv, fake_clock, num_records=3, include_index=False, include_briefing=False
        )
        plan_id = str(plan["plan_id"])
        planner.approve_plan(plan_id)

        # Expire tokens right after first Log completes
        verifies = 0

        def _expire_midway(boundary: str, _op_id: str) -> None:
            nonlocal verifies
            if boundary == "after_verification_before_persist":
                verifies += 1
                if verifies == 1:
                    srv.state.expire_all_access_tokens()

        engine = ExecutionEngine(
            db=tmp_db,
            registry=reg,
            adapter=adapter,
            lock_dir=tmp_path / "locks",
            fault_hook=_expire_midway,
        )
        rep1 = await engine.execute_plan(plan_id)
        assert rep1.plan_status == PlanStatus.PAUSED
        assert rep1.exit_code == ExitCode.AUTHORIZATION_REQUIRED
        assert len(srv.state.ground_truth_logs("acct_primary")) == 1

        # Scenario H: Attempt to resume using a DIFFERENT authenticated account (acct_secondary)!
        wrong_tok = srv.state.issue_token("acct_secondary")
        wrong_adapter = SandbarMCPAdapter(
            server_url=srv.mcp_url,
            scheduler=AccountRateScheduler(
                tmp_db, "acct_secondary", min_interval_seconds=2.0, clock=fake_clock
            ),
            bearer_token=wrong_tok["access_token"],
            allow_localhost_http=True,
        )
        wrong_engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=wrong_adapter, lock_dir=tmp_path / "locks"
        )
        with pytest.raises(AccountMismatchError):
            await wrong_engine.execute_plan(plan_id)
        assert len(srv.state.ground_truth_logs("acct_secondary")) == 0

        # Renew valid token for the ORIGINAL bound account (acct_primary) and resume safely!
        new_tok = srv.state.issue_token("acct_primary")
        renewed_adapter = SandbarMCPAdapter(
            server_url=srv.mcp_url,
            scheduler=AccountRateScheduler(
                tmp_db, "acct_primary", min_interval_seconds=2.0, clock=fake_clock
            ),
            bearer_token=new_tok["access_token"],
            allow_localhost_http=True,
        )
        resumed_engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=renewed_adapter, lock_dir=tmp_path / "locks"
        )
        rep_final = await resumed_engine.execute_plan(plan_id)
        assert rep_final.plan_status == PlanStatus.COMPLETED
        assert len(srv.state.ground_truth_logs("acct_primary")) == 3


@pytest.mark.asyncio
async def test_scenario_i_existing_unrelated_user_content_remains_untouched(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario I: Pre-existing personal user Logs in Memory folder are strictly untouched."""
    state = MockSandbarState(MockServerConfig())
    folder = state.seed_folder("acct_primary", "Memory", instruction=None)
    user_log = state.seed_user_log(
        "acct_primary",
        title="My Personal Journal Entry",
        body="Unrelated personal reflection authored directly by user.",
        folder_id=folder["id"],
        created_via_mcp=False,
    )
    with RunningMockServer(state) as srv:
        reg, adapter, planner, plan = await _setup_env(
            tmp_db, srv, fake_clock, num_records=2, include_index=False, include_briefing=False
        )
        planner.approve_plan(str(plan["plan_id"]))
        engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
        )
        rep = await engine.execute_plan(str(plan["plan_id"]))
        assert rep.plan_status == PlanStatus.COMPLETED

        # User's pre-existing Log MUST be bit-for-bit identical!
        gt = {x["id"]: x for x in srv.state.ground_truth_logs("acct_primary")}
        assert gt[user_log["id"]]["title"] == "My Personal Journal Entry"
        assert (
            gt[user_log["id"]]["body"] == "Unrelated personal reflection authored directly by user."
        )
        assert len(gt) == 3  # 1 user log + 2 managed logs


@pytest.mark.asyncio
async def test_scenario_j_duplicate_memory_folders_blocks_planning_and_preflight(
    tmp_db: Database, fake_clock: FakeClock
) -> None:
    """Scenario J: Multiple remote folders named 'Memory' MUST block until disambiguated."""
    state = MockSandbarState(MockServerConfig())
    state.seed_folder("acct_primary", "Memory", folder_id="fld_mem_1")
    state.seed_folder("acct_primary", "Memory", folder_id="fld_mem_2")
    with (
        RunningMockServer(state) as srv,
        pytest.raises(StreamMemoryError, match="Ambiguous remote state: found 2 folders"),
    ):
        await _setup_env(tmp_db, srv, fake_clock, num_records=1)


@pytest.mark.asyncio
async def test_scenario_k_unsupported_editing_vs_supported_editing(
    tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario K: Revised canonical record when remote edit is unsupported emits MANUAL_REPLACEMENT_REQUIRED."""
    # Part 1: Editing UNSUPPORTED (Sandbar default)
    state_no_edit = MockSandbarState(MockServerConfig(supports_update_log=False))
    with RunningMockServer(state_no_edit) as srv:
        db = Database(tmp_path / "no_edit.db")
        try:
            reg, adapter, planner, plan = await _setup_env(
                db, srv, fake_clock, num_records=1, include_index=False, include_briefing=False
            )
            planner.approve_plan(str(plan["plan_id"]))
            engine = ExecutionEngine(
                db=db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks1"
            )
            assert (
                await engine.execute_plan(str(plan["plan_id"]))
            ).plan_status == PlanStatus.COMPLETED
            assert len(srv.state.ground_truth_logs("acct_primary")) == 1

            # Update canonical record locally
            reg.upsert_record(
                MemoryRecordInput(
                    logical_id="syn_core_instructions",
                    title="AI Operating Instructions",
                    category="CORE",
                    body="Revised operating instructions with stricter voice brevity.",
                    inclusion_decision=InclusionDecision.APPROVED,
                )
            )
            compile_memory(reg, include_index=False, include_briefing=False)
            remote2 = await observe_remote_state(adapter)
            assert adapter.capabilities is not None
            plan2 = planner.build_plan(
                mode=ExecutionMode.MOCK,
                account_binding_hash=str(plan["account_binding_hash"]),
                capabilities=adapter.capabilities,
                remote_state=remote2,
            )
            assert plan2["summary"]["manual_actions_required"] == 1
            assert (
                plan2["operations"][0]["op_type"] == OperationType.MANUAL_REPLACEMENT_REQUIRED.value
            )
            assert plan2["operations"][0]["state"] == OperationState.BLOCKED.value
            # Account is NOT flooded with duplicate append-only Logs!
            assert len(srv.state.ground_truth_logs("acct_primary")) == 1
        finally:
            db.close()

    # Part 2: Editing SUPPORTED variant (`supports_update_log=True` + `tool_style="log"` + `idempotency_key`)
    state_edit = MockSandbarState(
        MockServerConfig(supports_update_log=True, supports_idempotency_key=True, tool_style="log")
    )
    with RunningMockServer(state_edit) as srv2:
        db2 = Database(tmp_path / "with_edit.db")
        try:
            reg2, adapter2, planner2, plan_a = await _setup_env(
                db2, srv2, fake_clock, num_records=1, include_index=False, include_briefing=False
            )
            planner2.approve_plan(str(plan_a["plan_id"]))
            engine2 = ExecutionEngine(
                db=db2, registry=reg2, adapter=adapter2, lock_dir=tmp_path / "locks2"
            )
            assert (
                await engine2.execute_plan(str(plan_a["plan_id"]))
            ).plan_status == PlanStatus.COMPLETED

            reg2.upsert_record(
                MemoryRecordInput(
                    logical_id="syn_core_instructions",
                    title="AI Operating Instructions",
                    category="CORE",
                    body="In-place updated operating instructions.",
                    inclusion_decision=InclusionDecision.APPROVED,
                )
            )
            compile_memory(reg2, include_index=False, include_briefing=False)
            remote_b = await observe_remote_state(adapter2)
            assert adapter2.capabilities is not None
            plan_b = planner2.build_plan(
                mode=ExecutionMode.MOCK,
                account_binding_hash=str(plan_a["account_binding_hash"]),
                capabilities=adapter2.capabilities,
                remote_state=remote_b,
            )
            assert any(o["op_type"] == OperationType.UPDATE_LOG.value for o in plan_b["operations"])
            planner2.approve_plan(str(plan_b["plan_id"]))
            rep_b = await engine2.execute_plan(str(plan_b["plan_id"]))
            assert rep_b.plan_status == PlanStatus.COMPLETED
            gt_logs = srv2.state.ground_truth_logs("acct_primary")
            assert len(gt_logs) == 1
            assert "In-place updated operating instructions." in gt_logs[0]["body"]
        finally:
            db2.close()


@pytest.mark.asyncio
async def test_scenario_l_server_schema_drift_invalidates_plan_and_stops(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario L: MCP server schema changes after plan approval -> SchemaDriftError & plan invalidated!"""
    state = MockSandbarState(MockServerConfig(schema_version_tag="v1"))
    with RunningMockServer(state) as srv:
        reg, adapter, planner, plan = await _setup_env(
            tmp_db, srv, fake_clock, num_records=1, include_index=False, include_briefing=False
        )
        plan_id = str(plan["plan_id"])
        planner.approve_plan(plan_id)

        # Server mutates its advertised tool schema after approval!
        srv.state.config.schema_version_tag = "v2-breaking-change"

        engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
        )
        with pytest.raises(SchemaDriftError):
            await engine.execute_plan(plan_id)

        assert planner.get_plan(plan_id)["status"] == PlanStatus.INVALIDATED.value
        assert len(srv.state.ground_truth_logs("acct_primary")) == 0


@pytest.mark.asyncio
async def test_scenario_m_n_and_o_privacy_rejection_conflicts_and_concurrency(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    """Scenario M (Privacy rejection) + Scenario N (Contradiction reconciliation) + Scenario O (Concurrent writer lock)."""
    reg = KnowledgeRegistry(tmp_db)
    # Scenario M: Secret/sensitive record injected alongside valid record
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="valid_pref",
            title="Display Preference",
            category="PREFERENCES",
            canonical_subject="Display Preference",
            body="Prefers crisp high-DPI monitor with 120Hz+ refresh for M2 MacBook Air.",
            evidence_class=EvidenceClass.USER_CONFIRMED,
            effective_date="2026-11-20",
            observed_date="2026-11-20",
            last_confirmed_date="2026-11-20",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    # Scenario N: Older contradictory record on same subject
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="stale_pref",
            title="Old Display Preference",
            category="PREFERENCES",
            canonical_subject="Display Preference",
            body="Prefers 60Hz 1080p monitor.",
            evidence_class=EvidenceClass.INFERRED,
            effective_date="2025-02-01",
            observed_date="2025-02-01",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    # Scenario M: Excluded private financial balance
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="sensitive_balance",
            title="Bank Summary",
            category="PERSONAL",
            body="Brokerage account balance is $125,000.00.",
            privacy_classification=PrivacyClassification.PERSONAL_APPROVED,
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )

    reconcile_registry(reg)
    evaluate_registry_privacy(reg)
    compile_memory(reg, include_index=False, include_briefing=False)

    state = MockSandbarState(MockServerConfig())
    with RunningMockServer(state) as srv:
        tok = srv.state.issue_token("acct_primary")
        sched = AccountRateScheduler(
            tmp_db, "acct_primary", min_interval_seconds=2.0, clock=fake_clock
        )
        adapter = SandbarMCPAdapter(
            server_url=srv.mcp_url,
            scheduler=sched,
            bearer_token=tok["access_token"],
            allow_localhost_http=True,
        )
        caps = await adapter.discover_capabilities()
        CapabilityStore(tmp_db).save_snapshot(caps)
        remote = await observe_remote_state(adapter)
        binding = AccountBindingManager(tmp_db).upsert_binding(
            profile_name="default",
            server_url=srv.mcp_url,
            issuer=srv.state.base_url,
            account_id="acct_primary",
            account_id_verified=True,
            confirmed_by_user=True,
        )
        planner = ImportPlanner(tmp_db, reg)
        plan = planner.build_plan(
            mode=ExecutionMode.MOCK,
            account_binding_hash=binding["binding_hash"],
            capabilities=caps,
            remote_state=remote,
        )
        planner.approve_plan(str(plan["plan_id"]))

        # Scenario O: Hold writer lock for same account scope -> engine MUST fail closed!
        external_lock = AccountWriterLock(
            tmp_path / "locks",
            canonical_account_scope(
                server_url=srv.mcp_url, account_id="acct_primary", profile_name="default"
            ),
        )
        with external_lock:
            engine = ExecutionEngine(
                db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
            )
            with pytest.raises(LockContentionError):
                await engine.execute_plan(str(plan["plan_id"]))

        # Release lock -> execute -> ONLY the newer clean record is uploaded!
        engine = ExecutionEngine(
            db=tmp_db, registry=reg, adapter=adapter, lock_dir=tmp_path / "locks"
        )
        rep = await engine.execute_plan(str(plan["plan_id"]))
        assert rep.plan_status == PlanStatus.COMPLETED
        gt_logs = srv.state.ground_truth_logs("acct_primary")
        assert len(gt_logs) == 1
        assert "120Hz+" in gt_logs[0]["body"]
        assert "125,000" not in gt_logs[0]["body"]
        assert "60Hz" not in gt_logs[0]["body"]
