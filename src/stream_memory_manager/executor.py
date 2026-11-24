"""Durable Operation Journal, Conservative Execution Engine, Verification, and Ambiguous-Commit Recovery.

Hardened against all distributed-systems and security audit findings:
- Dedicated post-write pause states (`PAUSED_VERIFICATION_AUTH`, `PAUSED_VERIFICATION_RATE_LIMIT`)
  eliminate the 2-hop re-dispatch bypass on `resume` and false `CANCELLED_BEFORE_WRITE` on `pause`.
- Atomic SQLite commit combining `VERIFIED` transition + `registry.mark_remote_verified()`.
- Complete `UPDATE_LOG` verification, privacy preflight, and stale-read bounded retries.
- Separate read-only reconcile preflight so `INVALIDATED` plans can still reconcile uncertain writes.
- Unified canonical account-scoped single-writer lock across all plans for the same account.
"""

from __future__ import annotations

import json
import signal
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stream_memory_manager.auth import AccountBindingManager
from stream_memory_manager.capabilities import CapabilityStore
from stream_memory_manager.compiler import normalize_remote_text, validate_log_payload
from stream_memory_manager.db import Database
from stream_memory_manager.locking import AccountWriterLock
from stream_memory_manager.mcp_adapter import RemoteLog, SandbarMCPAdapter
from stream_memory_manager.models import (
    AccountMismatchError,
    AmbiguousWriteError,
    ApprovalRequiredError,
    AuthorizationRequiredError,
    CapabilityUnsupportedError,
    ErrorClass,
    ExecutionMode,
    ExitCode,
    OperationState,
    OperationType,
    PlanStatus,
    PrivacyViolationError,
    RateLimitError,
    RemoteSyncStatus,
    RequestBudget,
    SchemaDriftError,
    StreamMemoryError,
    utc_now_iso,
)
from stream_memory_manager.planner import ImportPlanner
from stream_memory_manager.privacy import assert_payload_safe, assert_record_exportable
from stream_memory_manager.rate_limit import BudgetTracker
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import (
    canonical_account_scope,
    canonical_json_hash,
    redact_secrets,
)
from stream_memory_manager.state_machine import is_blocking, is_terminal, validate_transition

FaultHook = Callable[[str, str], None]


@dataclass
class ExecutionReport:
    plan_id: str
    plan_status: PlanStatus
    exit_code: ExitCode
    verified_count: int
    pending_count: int
    uncertain_count: int
    blocked_count: int
    conflicted_count: int
    failed_count: int
    cancelled_count: int
    paused_reason: str | None
    budget_snapshot: dict[str, int]
    next_safe_action: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "plan_status": self.plan_status.value,
            "exit_code": int(self.exit_code),
            "verified_count": self.verified_count,
            "pending_count": self.pending_count,
            "uncertain_count": self.uncertain_count,
            "blocked_count": self.blocked_count,
            "conflicted_count": self.conflicted_count,
            "failed_count": self.failed_count,
            "cancelled_count": self.cancelled_count,
            "paused_reason": self.paused_reason,
            "budget_snapshot": self.budget_snapshot,
            "next_safe_action": self.next_safe_action,
            "details": self.details,
        }


class OperationJournal:
    """Durable SQLite-backed state-machine journal for every remote mutation."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def get_op(self, op_id: str) -> dict[str, Any]:
        row = self.db.conn.execute("SELECT * FROM operations WHERE op_id = ?;", (op_id,)).fetchone()
        if not row:
            raise StreamMemoryError(
                f"Operation not found: {op_id}",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        d = dict(row)
        d["payload"] = json.loads(str(d["payload_json"]))
        return d

    def list_ops(self, plan_id: str) -> list[dict[str, Any]]:
        rows = self.db.conn.execute(
            "SELECT * FROM operations WHERE plan_id = ? ORDER BY sequence_num ASC;", (plan_id,)
        ).fetchall()
        return [{**dict(r), "payload": json.loads(str(r["payload_json"]))} for r in rows]

    def transition(
        self,
        op_id: str,
        to_state: OperationState,
        *,
        error_class: ErrorClass = ErrorClass.NONE,
        error_message: str | None = None,
        increment_attempt: bool = False,
        increment_verification: bool = False,
        request_started: bool = False,
        response_received: bool = False,
        response_status: str | None = None,
        remote_id: str | None = None,
        remote_last_update_ts: int | None = None,
        target_folder_id: str | None = None,
        verified_postcondition: dict[str, Any] | None = None,
        recovery_requirement: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.transaction() as conn:
            row = conn.execute("SELECT * FROM operations WHERE op_id = ?;", (op_id,)).fetchone()
            if not row:
                raise StreamMemoryError(f"Operation not found: {op_id}")
            current = OperationState(str(row["state"]))
            validate_transition(current, to_state, op_id=op_id)

            new_attempts = int(row["attempt_count"]) + (1 if increment_attempt else 0)
            new_ver = int(row["verification_attempts"]) + (1 if increment_verification else 0)
            req_start = now if request_started else row["request_started_at"]
            resp_recv = now if response_received else row["response_received_at"]
            resp_stat = response_status if response_status is not None else row["response_status"]
            rid = remote_id if remote_id is not None else row["remote_id"]
            rlu = (
                remote_last_update_ts
                if remote_last_update_ts is not None
                else row["remote_last_update_ts"]
            )
            tfid = target_folder_id if target_folder_id is not None else row["target_folder_id"]
            vpost = (
                json.dumps(verified_postcondition, sort_keys=True)
                if verified_postcondition is not None
                else row["verified_postcondition_json"]
            )
            rec_req = (
                recovery_requirement
                if recovery_requirement is not None
                else row["recovery_requirement"]
            )
            safe_err = redact_secrets(error_message) if error_message else None

            conn.execute(
                """
                UPDATE operations
                SET state = ?, attempt_count = ?, verification_attempts = ?,
                    last_error_class = ?, last_error_message = ?,
                    request_started_at = ?, response_received_at = ?, response_status = ?,
                    remote_id = ?, remote_last_update_ts = ?, target_folder_id = ?,
                    verified_postcondition_json = ?, recovery_requirement = ?, updated_at = ?
                WHERE op_id = ?;
                """,
                (
                    to_state.value,
                    new_attempts,
                    new_ver,
                    error_class.value,
                    safe_err,
                    req_start,
                    resp_recv,
                    resp_stat,
                    rid,
                    rlu,
                    tfid,
                    vpost,
                    rec_req,
                    now,
                    op_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO operation_events (op_id, plan_id, from_state, to_state, error_class, detail_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    op_id,
                    str(row["plan_id"]),
                    current.value,
                    to_state.value,
                    error_class.value,
                    json.dumps(detail or {}, sort_keys=True),
                    now,
                ),
            )
        return self.get_op(op_id)

    def recover_interrupted_in_flight(self, plan_id: str) -> dict[str, list[str]]:
        """Crash recovery on startup/resume:
        - Any `REQUEST_IN_FLIGHT` op MUST become `UNCERTAIN_REMOTE_OUTCOME` (Invariant 5 & 6).
        - Any `REQUEST_PREPARED` op (persisted strictly before socket dispatch) safely returns to `READY`.
        """
        promoted_uncertain: list[str] = []
        reset_prepared: list[str] = []
        for op in self.list_ops(plan_id):
            st = OperationState(str(op["state"]))
            op_id = str(op["op_id"])
            if st == OperationState.REQUEST_IN_FLIGHT:
                self.transition(
                    op_id,
                    OperationState.UNCERTAIN_REMOTE_OUTCOME,
                    error_class=ErrorClass.POTENTIALLY_COMMITTED_WRITE,
                    error_message="Process interrupted while write request was in flight; outcome uncertain.",
                    recovery_requirement="Run `stream-memory reconcile` to verify remote state before resuming.",
                    detail={"recovery_event": "crash_recovery_in_flight"},
                )
                promoted_uncertain.append(op_id)
            elif st == OperationState.REQUEST_PREPARED:
                self.transition(
                    op_id,
                    OperationState.READY,
                    detail={"recovery_event": "crash_recovery_pre_dispatch"},
                )
                reset_prepared.append(op_id)
        return {"promoted_uncertain": promoted_uncertain, "reset_prepared": reset_prepared}


class ExecutionEngine:
    """Conservative, journaled, verifiable execution & reconciliation engine."""

    def __init__(
        self,
        *,
        db: Database,
        registry: KnowledgeRegistry,
        adapter: SandbarMCPAdapter,
        lock_dir: Path,
        fault_hook: FaultHook | None = None,
    ) -> None:
        self.db = db
        self.registry = registry
        self.adapter = adapter
        self.lock_dir = lock_dir
        self.journal = OperationJournal(db)
        self.planner = ImportPlanner(db, registry)
        self.cap_store = CapabilityStore(db)
        self.bindings = AccountBindingManager(db)
        self.fault_hook = fault_hook
        self._shutdown_requested = False

    def request_shutdown(self) -> None:
        self._shutdown_requested = True

    def _fire_fault(self, boundary: str, op_id: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(boundary, op_id)

    def _lock_scope_for_plan(self, plan: dict[str, Any]) -> str:
        binding = self.bindings.get_binding(str(plan["account_binding_hash"]))
        if binding is None:
            return str(plan["account_binding_hash"])
        return canonical_account_scope(
            server_url=str(binding["server_url"]),
            account_id=binding.get("account_id"),
            profile_name=str(binding["profile_name"]),
        )

    def _set_plan_status(self, plan_id: str, status: PlanStatus) -> None:
        with self.db.transaction() as conn:
            conn.execute("UPDATE plans SET status = ? WHERE plan_id = ?;", (status.value, plan_id))

    def _update_plan_folder_id(self, plan_id: str, folder_id: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE plans SET target_folder_id = ? WHERE plan_id = ?;",
                (folder_id, plan_id),
            )
            conn.execute(
                """
                UPDATE operations
                SET target_folder_id = ?
                WHERE plan_id = ? AND target_folder_id IS NULL;
                """,
                (folder_id, plan_id),
            )

    def _summarize_plan(
        self,
        plan_id: str,
        budget: BudgetTracker,
        *,
        paused_reason: str | None = None,
        details: dict[str, Any] | None = None,
        preserve_invalidated: bool = False,
    ) -> ExecutionReport:
        ops = self.journal.list_ops(plan_id)
        counts = {s: 0 for s in OperationState}
        for op in ops:
            counts[OperationState(str(op["state"]))] += 1

        verified = counts[OperationState.VERIFIED]
        uncertain = (
            counts[OperationState.UNCERTAIN_REMOTE_OUTCOME]
            + counts[OperationState.REQUEST_IN_FLIGHT]
        )
        blocked = counts[OperationState.BLOCKED]
        conflicted = counts[OperationState.CONFLICTED]
        failed = counts[OperationState.FAILED_CONFIRMED]
        cancelled = counts[OperationState.CANCELLED_BEFORE_WRITE]
        paused_auth = (
            counts[OperationState.PAUSED_AUTHORIZATION]
            + counts[OperationState.PAUSED_VERIFICATION_AUTH]
        )
        paused_rl = (
            counts[OperationState.PAUSED_RATE_LIMIT]
            + counts[OperationState.PAUSED_VERIFICATION_RATE_LIMIT]
        )
        awaiting_ver = (
            counts[OperationState.AWAITING_VERIFICATION] + counts[OperationState.ACKNOWLEDGED]
        )
        pending = (
            counts[OperationState.PLANNED]
            + counts[OperationState.APPROVED]
            + counts[OperationState.READY]
            + counts[OperationState.REQUEST_PREPARED]
            + counts[OperationState.RETRY_WAIT]
        )

        # Invariant 16: Completion honesty! Never report COMPLETED while anything is unresolved.
        if uncertain > 0:
            plan_status = PlanStatus.BLOCKED
            exit_code = ExitCode.AMBIGUOUS_REMOTE_OUTCOME
            next_action = "reconcile"
            paused_reason = paused_reason or "UNCERTAIN_REMOTE_OUTCOME"
        elif paused_auth > 0 or paused_reason == "AUTHORIZATION_REQUIRED":
            plan_status = PlanStatus.PAUSED
            exit_code = ExitCode.AUTHORIZATION_REQUIRED
            next_action = "auth connect && reconcile && resume"
            paused_reason = paused_reason or "PAUSED_AUTHORIZATION"
        elif conflicted > 0 or blocked > 0:
            plan_status = PlanStatus.BLOCKED
            exit_code = ExitCode.BLOCKED_CONFLICT
            next_action = "inspect conflicts/blocked operations and reconcile or replan"
            paused_reason = paused_reason or ("CONFLICTED" if conflicted else "BLOCKED")
        elif paused_rl > 0 or paused_reason in (
            "RATE_LIMITED",
            "SHUTDOWN_REQUESTED",
            "ERROR_THRESHOLD",
            "READ_TRANSIENT",
            "BUDGET_EXHAUSTED",
        ):
            plan_status = PlanStatus.PAUSED
            exit_code = ExitCode.TEMPORARY_FAILURE
            next_action = (
                "reconcile" if counts[OperationState.PAUSED_VERIFICATION_RATE_LIMIT] else "resume"
            )
        elif awaiting_ver > 0:
            plan_status = PlanStatus.PARTIALLY_VERIFIED
            exit_code = ExitCode.PARTIAL_VERIFICATION
            next_action = "verify"
            paused_reason = paused_reason or "AWAITING_VERIFICATION"
        elif failed > 0:
            plan_status = PlanStatus.BLOCKED
            exit_code = ExitCode.PERMANENT_FAILURE
            next_action = "inspect failed operations and replan"
            paused_reason = paused_reason or "FAILED_CONFIRMED"
        elif pending > 0:
            plan_status = PlanStatus.PAUSED
            exit_code = ExitCode.PARTIAL_VERIFICATION
            next_action = "resume"
        else:
            plan_status = PlanStatus.COMPLETED
            exit_code = ExitCode.SUCCESS
            next_action = "none (plan verified complete)"

        cur_plan = self.planner.get_plan(plan_id)
        if not (preserve_invalidated and str(cur_plan["status"]) == PlanStatus.INVALIDATED.value):
            self._set_plan_status(plan_id, plan_status)
        else:
            plan_status = PlanStatus.INVALIDATED

        return ExecutionReport(
            plan_id=plan_id,
            plan_status=plan_status,
            exit_code=exit_code,
            verified_count=verified,
            pending_count=pending + awaiting_ver + paused_auth + paused_rl,
            uncertain_count=uncertain,
            blocked_count=blocked,
            conflicted_count=conflicted,
            failed_count=failed,
            cancelled_count=cancelled,
            paused_reason=paused_reason,
            budget_snapshot=budget.snapshot(),
            next_safe_action=next_action,
            details=details or {},
        )

    async def _preflight(
        self,
        plan: dict[str, Any],
        *,
        for_reconcile_only: bool = False,
        expected_mode: ExecutionMode | None = None,
    ) -> tuple[str | None, dict[str, Any]]:
        """Preflight gate separated cleanly between write execution and read-only reconciliation."""
        self.db.verify_integrity()

        plan_id = str(plan["plan_id"])
        status = PlanStatus(str(plan["status"]))

        if not for_reconcile_only:
            if status == PlanStatus.DRAFT or not plan.get("approved_at"):
                raise ApprovalRequiredError(
                    f"Plan {plan_id} is not explicitly approved (Invariant 1). Run `stream-memory approve --plan-id {plan_id}`."
                )
            if status in (PlanStatus.INVALIDATED, PlanStatus.CANCELLED):
                raise ApprovalRequiredError(
                    f"Plan {plan_id} has status {status.value} and cannot execute."
                )
            if str(plan["mode"]) == ExecutionMode.DRY_RUN.value:
                raise ApprovalRequiredError(
                    f"Plan {plan_id} was generated in dry-run mode and cannot mutate remote state."
                )
            if expected_mode is not None and str(plan["mode"]) != expected_mode.value:
                raise ApprovalRequiredError(
                    f"Mode mismatch: plan {plan_id} was built for mode={plan['mode']!r}, "
                    f"refusing to execute under mode={expected_mode.value!r}."
                )

        # Discover capabilities (and check drift strictly for writes; allow read-only reconcile!)
        live_caps = await self.adapter.discover_capabilities()
        self.cap_store.save_snapshot(live_caps)
        if not for_reconcile_only:
            try:
                self.cap_store.assert_compatible(str(plan["capability_fingerprint"]), live_caps)
            except SchemaDriftError:
                self.planner.invalidate_plan(plan_id, "SERVER_SCHEMA_DRIFT")
                raise

        # Verify Account Binding AND OAuth Issuer (Audit R14)
        obs_account_id, _verified, obs_issuer = await self.adapter.get_account_identity()
        self.bindings.assert_matches_expected(
            expected_binding_hash=str(plan["account_binding_hash"]),
            observed_server_url=self.adapter.server_url,
            observed_account_id=obs_account_id,
            observed_issuer=obs_issuer,
        )

        # For writes: re-verify privacy, length, and revision freshness on EVERY outgoing payload (Audit R13)
        if not for_reconcile_only:
            for op in plan["operations"]:
                if is_terminal(OperationState(str(op["state"]))):
                    continue
                op_type = str(op["op_type"])
                payload = op["payload"]
                if op_type in (OperationType.CREATE_LOG.value, OperationType.UPDATE_LOG.value):
                    title = str(payload.get("title", ""))
                    body = str(payload.get("body", ""))
                    validate_log_payload(title, body)
                    assert_payload_safe(title, body, label=str(op["op_id"]))
                    rec_lid = str(payload.get("logical_id", ""))
                    if not rec_lid:
                        raise PrivacyViolationError(
                            f"Operation {op['op_id']} ({op_type}) missing logical_id; refusing blind upload."
                        )
                    if rec_lid != "core_knowledge_index":
                        rec = self.registry.get_record(rec_lid)
                        if rec is None:
                            raise PrivacyViolationError(
                                f"Operation {op['op_id']} references missing canonical record {rec_lid!r}."
                            )
                        expected_rev = payload.get("revision_number") or op.get("revision_number")
                        if expected_rev is not None and int(rec["current_revision"]) != int(
                            expected_rev
                        ):
                            raise PrivacyViolationError(
                                f"Operation {op['op_id']} payload revision {expected_rev} is stale "
                                f"(current rev {rec['current_revision']}); recompile and replan."
                            )
                        assert_record_exportable(rec)
                elif op_type == OperationType.UPDATE_FOLDER_INSTRUCTION.value:
                    assert_payload_safe(
                        "", str(payload.get("instruction", "")), label=str(op["op_id"])
                    )
                elif op_type == OperationType.SET_BRIEFING.value:
                    assert_payload_safe("", str(payload.get("body", "")), label=str(op["op_id"]))

        # Verify target folder uniqueness AND presence if bound at plan time (Audit R9)
        target_name = str(plan["target_folder_name"])
        bound_folder_id: str | None = plan.get("target_folder_id")
        folder_id: str | None = bound_folder_id
        if live_caps.supports_list_folders:
            folders = await self.adapter.list_folders()
            matches = [f for f in folders if f.name == target_name]
            if len(matches) > 1:
                raise StreamMemoryError(
                    f"Preflight blocked: {len(matches)} remote folders named {target_name!r} exist.",
                    error_class=ErrorClass.CONFLICT_ERROR,
                    exit_code=ExitCode.BLOCKED_CONFLICT,
                    details={"folder_ids": [m.folder_id for m in matches]},
                )
            if len(matches) == 1:
                if bound_folder_id and matches[0].folder_id != bound_folder_id:
                    raise StreamMemoryError(
                        f"Folder identity drift: plan bound to {bound_folder_id!r}, remote {target_name!r} is {matches[0].folder_id!r}",
                        error_class=ErrorClass.CONFLICT_ERROR,
                        exit_code=ExitCode.BLOCKED_CONFLICT,
                    )
                folder_id = matches[0].folder_id
                self._update_plan_folder_id(plan_id, folder_id)
            elif bound_folder_id and not for_reconcile_only:
                raise StreamMemoryError(
                    f"Bound target folder {target_name!r} ({bound_folder_id}) no longer exists remotely; replan.",
                    error_class=ErrorClass.CONFLICT_ERROR,
                    exit_code=ExitCode.BLOCKED_CONFLICT,
                )

        return folder_id, {
            "account_id": obs_account_id,
            "issuer": obs_issuer,
            "schema_fingerprint": live_caps.schema_fingerprint,
            "resolved_folder_id": folder_id,
        }

    async def reconcile_plan(self, plan_id: str) -> ExecutionReport:
        """Read-only reconciliation for UNCERTAIN, AWAITING_VERIFICATION, PAUSED_VERIFICATION_*, and BLOCKED ops.

        NEVER issues a mutating write. Adopts unambiguous verified remote matches; blocks unresolved ones.
        """
        plan = self.planner.get_plan(plan_id)
        budget = BudgetTracker(RequestBudget.model_validate(plan["budget"]))
        reconcilable_states = {
            OperationState.UNCERTAIN_REMOTE_OUTCOME,
            OperationState.AWAITING_VERIFICATION,
            OperationState.ACKNOWLEDGED,
            OperationState.PAUSED_VERIFICATION_AUTH,
            OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
        }

        with AccountWriterLock(self.lock_dir, self._lock_scope_for_plan(plan)):
            crash_rec = self.journal.recover_interrupted_in_flight(plan_id)

            try:
                folder_id, preflight_info = await self._preflight(plan, for_reconcile_only=True)
            except AuthorizationRequiredError as exc:
                return self._summarize_plan(
                    plan_id,
                    budget,
                    paused_reason="AUTHORIZATION_REQUIRED",
                    details={"error": redact_secrets(str(exc))},
                    preserve_invalidated=True,
                )
            except RateLimitError as exc:
                delay, _ = self.adapter.scheduler.record_rate_limit(
                    retry_after_seconds=exc.retry_after_seconds
                )
                return self._summarize_plan(
                    plan_id,
                    budget,
                    paused_reason="RATE_LIMITED",
                    details={"retry_after": delay, "error": redact_secrets(str(exc))},
                    preserve_invalidated=True,
                )
            except (AccountMismatchError, SchemaDriftError) as exc:
                return self._summarize_plan(
                    plan_id,
                    budget,
                    paused_reason=exc.error_class.value,
                    details={"error": redact_secrets(str(exc))},
                    preserve_invalidated=True,
                )
            except StreamMemoryError as exc:
                return self._summarize_plan(
                    plan_id,
                    budget,
                    paused_reason="READ_TRANSIENT",
                    details={"error": redact_secrets(str(exc))},
                    preserve_invalidated=True,
                )

            reconciled_ids: list[str] = []
            still_blocked_ids: list[str] = []

            for op in self.journal.list_ops(plan_id):
                st = OperationState(str(op["state"]))
                is_reconcilable_blocked = (
                    st == OperationState.BLOCKED
                    and str(op.get("last_error_class", ""))
                    == ErrorClass.POTENTIALLY_COMMITTED_WRITE.value
                )
                if st not in reconcilable_states and not is_reconcilable_blocked:
                    continue
                op_id = str(op["op_id"])
                try:
                    budget.consume_reconciliation()
                except StreamMemoryError as exc:
                    return self._summarize_plan(
                        plan_id,
                        budget,
                        paused_reason="BUDGET_EXHAUSTED",
                        details={"error": str(exc)},
                        preserve_invalidated=True,
                    )
                try:
                    resolved = await self._reconcile_single_op(
                        op, folder_id=folder_id, budget=budget
                    )
                    if resolved:
                        reconciled_ids.append(op_id)
                        if str(op["op_type"]) == OperationType.RESOLVE_OR_CREATE_FOLDER.value:
                            refreshed = self.journal.get_op(op_id)
                            if refreshed.get("remote_id"):
                                folder_id = str(refreshed["remote_id"])
                                self._update_plan_folder_id(plan_id, folder_id)
                    else:
                        still_blocked_ids.append(op_id)
                except AuthorizationRequiredError as exc:
                    # Re-read live post-transition state (Audit R9) -> use PAUSED_VERIFICATION_AUTH!
                    live_st = OperationState(str(self.journal.get_op(op_id)["state"]))
                    if live_st == OperationState.AWAITING_VERIFICATION:
                        self.journal.transition(
                            op_id,
                            OperationState.PAUSED_VERIFICATION_AUTH,
                            error_class=ErrorClass.AUTHENTICATION_ERROR,
                            error_message=str(exc),
                        )
                    return self._summarize_plan(
                        plan_id,
                        budget,
                        paused_reason="AUTHORIZATION_REQUIRED",
                        details={"error": redact_secrets(str(exc))},
                        preserve_invalidated=True,
                    )
                except RateLimitError as exc:
                    delay, _ = self.adapter.scheduler.record_rate_limit(
                        retry_after_seconds=exc.retry_after_seconds
                    )
                    live_st = OperationState(str(self.journal.get_op(op_id)["state"]))
                    if live_st == OperationState.AWAITING_VERIFICATION:
                        self.journal.transition(
                            op_id,
                            OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
                            error_class=ErrorClass.RATE_LIMIT_ERROR,
                            error_message=str(exc),
                        )
                    return self._summarize_plan(
                        plan_id,
                        budget,
                        paused_reason="RATE_LIMITED",
                        details={"retry_after": delay, "error": redact_secrets(str(exc))},
                        preserve_invalidated=True,
                    )
                except StreamMemoryError as exc:
                    # Catch READ_TRANSIENT (e.g. 503 pagination failure) cleanly instead of crashing!
                    return self._summarize_plan(
                        plan_id,
                        budget,
                        paused_reason="READ_TRANSIENT",
                        details={"op_id": op_id, "error": redact_secrets(str(exc))},
                        preserve_invalidated=True,
                    )

            return self._summarize_plan(
                plan_id,
                budget,
                details={
                    "crash_recovery": crash_rec,
                    "preflight": preflight_info,
                    "reconciled": reconciled_ids,
                    "blocked_unresolved": still_blocked_ids,
                },
                preserve_invalidated=True,
            )

    async def _reconcile_single_op(
        self,
        op: dict[str, Any],
        *,
        folder_id: str | None,
        budget: BudgetTracker,
    ) -> bool:
        """Inspect remote evidence for one uncertain, paused-verification, or awaiting-verification op."""
        op_id = str(op["op_id"])
        op_type = OperationType(str(op["op_type"]))
        st = OperationState(str(op["state"]))
        payload = op["payload"]

        if st in (
            OperationState.UNCERTAIN_REMOTE_OUTCOME,
            OperationState.ACKNOWLEDGED,
            OperationState.PAUSED_VERIFICATION_AUTH,
            OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
            OperationState.BLOCKED,
        ):
            self.journal.transition(
                op_id,
                OperationState.AWAITING_VERIFICATION,
                detail={"event": "reconciliation_or_verification_started", "from": st.value},
            )

        max_ver_attempts = budget.budget.max_verification_attempts_per_op

        if op_type == OperationType.RESOLVE_OR_CREATE_FOLDER:
            for attempt in range(1, max_ver_attempts + 1):
                folders = await self.adapter.list_folders()
                matches = [f for f in folders if f.name == str(payload["name"])]
                if len(matches) == 1:
                    f = matches[0]
                    self.journal.transition(
                        op_id,
                        OperationState.VERIFIED,
                        increment_verification=True,
                        remote_id=f.folder_id,
                        remote_last_update_ts=f.last_update_ts,
                        target_folder_id=f.folder_id,
                        verified_postcondition={
                            "folder_id": f.folder_id,
                            "name": f.name,
                            "method": "list_folders",
                            "attempt": attempt,
                        },
                    )
                    return True
                if len(matches) > 1:
                    self.journal.transition(
                        op_id,
                        OperationState.CONFLICTED,
                        increment_verification=True,
                        error_class=ErrorClass.CONFLICT_ERROR,
                        error_message=f"Multiple remote folders named {payload['name']!r} found during reconciliation.",
                    )
                    return False
                if attempt < max_ver_attempts:
                    await self.adapter.scheduler.clock.sleep(
                        max(1.0, self.adapter.scheduler.min_interval_seconds)
                    )
            self.journal.transition(
                op_id,
                OperationState.BLOCKED,
                error_class=ErrorClass.POTENTIALLY_COMMITTED_WRITE,
                error_message="Uncertain folder creation could not be confirmed in remote folder list.",
                recovery_requirement="Inspect Stream folders manually and replan.",
            )
            return False

        if op_type in (OperationType.CREATE_LOG, OperationType.UPDATE_LOG):
            return await self._verify_or_adopt_log(op, folder_id=folder_id, budget=budget)

        if op_type == OperationType.UPDATE_FOLDER_INSTRUCTION:
            if not folder_id:
                self.journal.transition(
                    op_id,
                    OperationState.BLOCKED,
                    error_class=ErrorClass.VALIDATION_PERMANENT,
                    error_message="Missing target folder_id to verify folder instruction.",
                )
                return False
            expected_norm = normalize_remote_text(str(payload["instruction"]))
            for attempt in range(1, max_ver_attempts + 1):
                folders = await self.adapter.list_folders()
                match = next((f for f in folders if f.folder_id == folder_id), None)
                if match and normalize_remote_text(match.instruction or "") == expected_norm:
                    self.journal.transition(
                        op_id,
                        OperationState.VERIFIED,
                        increment_verification=True,
                        remote_id=match.folder_id,
                        remote_last_update_ts=match.last_update_ts,
                        verified_postcondition={
                            "instruction_verified": True,
                            "method": "list_folders",
                            "attempt": attempt,
                        },
                    )
                    return True
                if attempt < max_ver_attempts:
                    await self.adapter.scheduler.clock.sleep(
                        max(1.0, self.adapter.scheduler.min_interval_seconds)
                    )
            self.journal.transition(
                op_id,
                OperationState.BLOCKED,
                error_class=ErrorClass.POTENTIALLY_COMMITTED_WRITE,
                error_message="Folder instruction did not match expected text after bounded retries.",
            )
            return False

        if op_type == OperationType.SET_BRIEFING:
            if self.adapter.capabilities and self.adapter.capabilities.supports_get_briefing:
                expected_br = normalize_remote_text(str(payload["body"]))
                for attempt in range(1, max_ver_attempts + 1):
                    br = await self.adapter.get_briefing()
                    if br and normalize_remote_text(br.body) == expected_br:
                        self.journal.transition(
                            op_id,
                            OperationState.VERIFIED,
                            increment_verification=True,
                            verified_postcondition={
                                "briefing_verified": True,
                                "method": "get_briefing",
                                "attempt": attempt,
                            },
                        )
                        return True
                    if attempt < max_ver_attempts:
                        await self.adapter.scheduler.clock.sleep(
                            max(1.0, self.adapter.scheduler.min_interval_seconds)
                        )
            self.journal.transition(
                op_id,
                OperationState.BLOCKED,
                error_class=ErrorClass.POTENTIALLY_COMMITTED_WRITE,
                error_message="Could not independently verify briefing content after bounded retries.",
            )
            return False

        return False

    async def _verify_or_adopt_log(
        self,
        op: dict[str, Any],
        *,
        folder_id: str | None,
        budget: BudgetTracker,
    ) -> bool:
        """Bounded verification / adoption of a remote Log (handles indexing lag, stale reads, and UPDATE_LOG)."""
        op_id = str(op["op_id"])
        op_type = OperationType(str(op["op_type"]))
        payload = op["payload"]
        account_binding_hash = str(op["account_binding_hash"])
        expected_norm_hash = str(op["normalized_payload_hash"])
        expected_title = normalize_remote_text(str(payload["title"]))
        is_update = op_type == OperationType.UPDATE_LOG

        # For UPDATE_LOG, target remote_id is fixed in payload["remote_id"] (Audit R3)!
        known_rid: str | None = (
            str(payload["remote_id"])
            if is_update and payload.get("remote_id")
            else (str(op["remote_id"]) if op.get("remote_id") else None)
        )
        max_ver_attempts = budget.budget.max_verification_attempts_per_op

        # Scope claimed_ids strictly by account_binding_hash and active/verified non-failed ops (Audit R3/R9)
        claimed_rows = self.db.conn.execute(
            """
            SELECT remote_id FROM operations
            WHERE remote_id IS NOT NULL
              AND account_binding_hash = ?
              AND op_id != ?
              AND logical_id != ?
              AND state NOT IN ('FAILED_CONFIRMED', 'CANCELLED_BEFORE_WRITE');
            """,
            (account_binding_hash, op_id, str(op["logical_id"])),
        ).fetchall()
        claimed_ids = {str(r["remote_id"]) for r in claimed_rows}

        for attempt in range(1, max_ver_attempts + 1):
            self._fire_fault("during_verification", op_id)
            budget.verification_requests += 1
            candidate: RemoteLog | None = None
            method = ""

            # Strategy 1 (preferred): Direct read by server-issued durable ID
            if (
                known_rid
                and self.adapter.capabilities
                and self.adapter.capabilities.supports_get_artifact
            ):
                fetched = await self.adapter.get_artifact(known_rid)
                if fetched is not None:
                    # Guard Strategy 1 against claimed/user-authored wrong_id (Audit R9)
                    if not is_update and (
                        fetched.artifact_id in claimed_ids or fetched.created_via_mcp is False
                    ):
                        self.journal.transition(
                            op_id,
                            OperationState.CONFLICTED,
                            increment_verification=True,
                            error_class=ErrorClass.CONFLICT_ERROR,
                            error_message=f"Server returned remote ID {fetched.artifact_id!r} belonging to another or user-authored Log.",
                        )
                        return False
                    candidate = fetched
                    method = "get_artifact_by_id"

            # Strategy 2 (CREATE_LOG only, or UPDATE_LOG fallback lookup of exact known_rid): list_artifacts
            if (
                candidate is None
                and self.adapter.capabilities
                and self.adapter.capabilities.supports_list_artifacts
            ):
                listed = await self.adapter.list_artifacts(folder_id=folder_id)
                if is_update and known_rid:
                    match = next((rl for rl in listed if rl.artifact_id == known_rid), None)
                    if match is not None:
                        candidate = match
                        method = "list_artifacts_by_update_id"
                else:
                    listed = await self._hydrate_snippet_candidates(listed)
                    exact_matches, title_conflicts = _match_log_candidates(
                        listed,
                        expected_norm_hash=expected_norm_hash,
                        expected_title=expected_title,
                        folder_id=folder_id,
                        claimed_ids=claimed_ids,
                    )
                    if len(exact_matches) == 1:
                        candidate = exact_matches[0]
                        method = "list_artifacts_exact_hash"
                    elif len(exact_matches) > 1 or title_conflicts:
                        self.journal.transition(
                            op_id,
                            OperationState.CONFLICTED,
                            increment_verification=True,
                            error_class=ErrorClass.CONFLICT_ERROR,
                            error_message="Multiple matching Logs or title collision with differing body detected.",
                            detail={
                                "exact_match_ids": [m.artifact_id for m in exact_matches],
                                "title_conflict_ids": [m.artifact_id for m in title_conflicts],
                            },
                        )
                        return False

            # Strategy 3 (CREATE_LOG only): Bounded search fallback
            if (
                candidate is None
                and not is_update
                and self.adapter.capabilities
                and self.adapter.capabilities.supports_search
            ):
                found = await self.adapter.search_logs(str(payload["title"]), folder_id=folder_id)
                found = await self._hydrate_snippet_candidates(found)
                exact_matches, title_conflicts = _match_log_candidates(
                    found,
                    expected_norm_hash=expected_norm_hash,
                    expected_title=expected_title,
                    folder_id=folder_id,
                    claimed_ids=claimed_ids,
                )
                if len(exact_matches) == 1:
                    candidate = exact_matches[0]
                    method = "search_exact_hash"
                elif len(exact_matches) > 1 or title_conflicts:
                    self.journal.transition(
                        op_id,
                        OperationState.CONFLICTED,
                        increment_verification=True,
                        error_class=ErrorClass.CONFLICT_ERROR,
                        error_message="Ambiguous or conflicting search candidates during verification.",
                    )
                    return False

            if candidate is not None:
                cand_hash = canonical_json_hash(
                    {
                        "title": normalize_remote_text(candidate.title),
                        "body": normalize_remote_text(candidate.body),
                    }
                )
                if cand_hash != expected_norm_hash:
                    # On UPDATE_LOG (or replica read lag), retry within bounded window before declaring CONFLICTED!
                    if is_update and attempt < max_ver_attempts:
                        self.journal.transition(
                            op_id,
                            OperationState.AWAITING_VERIFICATION,
                            increment_verification=True,
                            detail={"attempt": attempt, "status": "stale_read_retry"},
                        )
                        await self.adapter.scheduler.clock.sleep(
                            max(1.0, self.adapter.scheduler.min_interval_seconds)
                        )
                        continue
                    self.journal.transition(
                        op_id,
                        OperationState.CONFLICTED,
                        increment_verification=True,
                        error_class=ErrorClass.CONFLICT_ERROR,
                        error_message="Remote Log content diverged from approved payload beyond normalization policy.",
                        detail={
                            "remote_id": candidate.artifact_id,
                            "expected_hash": expected_norm_hash,
                            "observed_hash": cand_hash,
                        },
                    )
                    return False

                # Folder membership check: never blindly claim folder_match=True if candidate.folder_id is None!
                folder_verified = True
                if folder_id:
                    if candidate.folder_id is not None:
                        if candidate.folder_id != folder_id:
                            self.journal.transition(
                                op_id,
                                OperationState.CONFLICTED,
                                increment_verification=True,
                                error_class=ErrorClass.CONFLICT_ERROR,
                                error_message=f"Remote Log filed in unexpected folder {candidate.folder_id!r}, expected {folder_id!r}",
                            )
                            return False
                    elif (
                        self.adapter.capabilities
                        and self.adapter.capabilities.supports_list_artifacts
                    ):
                        folder_items = await self.adapter.list_artifacts(folder_id=folder_id)
                        if not any(fi.artifact_id == candidate.artifact_id for fi in folder_items):
                            folder_verified = False

                if not folder_verified:
                    if attempt < max_ver_attempts:
                        self.journal.transition(
                            op_id,
                            OperationState.AWAITING_VERIFICATION,
                            increment_verification=True,
                            detail={"attempt": attempt, "status": "folder_membership_pending"},
                        )
                        await self.adapter.scheduler.clock.sleep(
                            max(1.0, self.adapter.scheduler.min_interval_seconds)
                        )
                        continue
                    self.journal.transition(
                        op_id,
                        OperationState.CONFLICTED,
                        increment_verification=True,
                        error_class=ErrorClass.CONFLICT_ERROR,
                        error_message=f"Remote Log {candidate.artifact_id!r} could not be confirmed inside folder {folder_id!r}.",
                    )
                    return False

                self._fire_fault("after_verification_before_persist", op_id)

                # Atomic single transaction for BOTH journal VERIFIED and registry sync metadata (Audit R9)!
                with self.db.transaction():
                    self.journal.transition(
                        op_id,
                        OperationState.VERIFIED,
                        increment_verification=True,
                        remote_id=candidate.artifact_id,
                        remote_last_update_ts=candidate.last_update_ts,
                        target_folder_id=candidate.folder_id or folder_id,
                        verified_postcondition={
                            "method": method,
                            "remote_id": candidate.artifact_id,
                            "normalized_hash_match": True,
                            "folder_match": True,
                            "attempt": attempt,
                        },
                    )
                    rec_lid = str(payload.get("logical_id", ""))
                    if rec_lid and self.registry.get_record(rec_lid) is not None:
                        self.registry.mark_remote_verified(
                            rec_lid,
                            remote_id=candidate.artifact_id,
                            remote_folder_id=candidate.folder_id or folder_id,
                            remote_last_update_ts=candidate.last_update_ts,
                        )
                return True

            # Not visible yet (search/indexing lag). Record bounded verification attempt.
            self.journal.transition(
                op_id,
                OperationState.AWAITING_VERIFICATION,
                increment_verification=True,
                detail={"attempt": attempt, "status": "not_yet_visible"},
            )
            if attempt < max_ver_attempts:
                await self.adapter.scheduler.clock.sleep(
                    max(1.0, self.adapter.scheduler.min_interval_seconds)
                )

        # Exhausted bounded verification window -> fail closed to BLOCKED! NEVER blindly re-create!
        self.journal.transition(
            op_id,
            OperationState.BLOCKED,
            error_class=ErrorClass.POTENTIALLY_COMMITTED_WRITE,
            error_message=(
                f"Remote Log could not be verified after {max_ver_attempts} bounded checks. "
                "Refusing to re-create to prevent duplicates (Invariant 6)."
            ),
            recovery_requirement="Inspect Stream Memory folder manually, then run `reconcile` or replan.",
        )
        return False

    async def _hydrate_snippet_candidates(self, items: list[RemoteLog]) -> list[RemoteLog]:
        """If search/list returns summary-only items with empty body, hydrate via get_artifact(id)."""
        if not (self.adapter.capabilities and self.adapter.capabilities.supports_get_artifact):
            return items
        hydrated: list[RemoteLog] = []
        for rl in items:
            if rl.artifact_id and (not rl.body.strip() or not rl.title.strip()):
                full = await self.adapter.get_artifact(rl.artifact_id)
                hydrated.append(full if full is not None else rl)
            else:
                hydrated.append(rl)
        return hydrated

    async def execute_plan(
        self,
        plan_id: str,
        *,
        expected_mode: ExecutionMode | None = None,
        install_signal_handlers: bool = False,
    ) -> ExecutionReport:
        """Execute or safely resume an explicitly approved plan with checkpointed batches."""
        plan = self.planner.get_plan(plan_id)
        budget = BudgetTracker(RequestBudget.model_validate(plan["budget"]))

        old_sigint = None
        old_sigterm = None
        if install_signal_handlers:

            def _handle_sig(_signum: int, _frame: Any) -> None:
                self.request_shutdown()

            old_sigint = signal.getsignal(signal.SIGINT)
            old_sigterm = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGINT, _handle_sig)
            signal.signal(signal.SIGTERM, _handle_sig)

        try:
            with AccountWriterLock(self.lock_dir, self._lock_scope_for_plan(plan)):
                # Step 1: Crash recovery before anything else
                crash_rec = self.journal.recover_interrupted_in_flight(plan_id)

                # Step 2: Refuse to issue new writes while any UNCERTAIN / PAUSED_VERIFICATION_* / CONFLICTED / BLOCKED op exists!
                pre_ops = self.journal.list_ops(plan_id)
                uncertain_ops = [
                    str(o["op_id"])
                    for o in pre_ops
                    if OperationState(str(o["state"])) == OperationState.UNCERTAIN_REMOTE_OUTCOME
                ]
                if uncertain_ops:
                    return self._summarize_plan(
                        plan_id,
                        budget,
                        paused_reason="UNCERTAIN_REMOTE_OUTCOME",
                        details={"uncertain_ops": uncertain_ops, "crash_recovery": crash_rec},
                    )
                blocked_or_conflicted = [
                    str(o["op_id"])
                    for o in pre_ops
                    if OperationState(str(o["state"]))
                    in (OperationState.BLOCKED, OperationState.CONFLICTED)
                ]
                if blocked_or_conflicted:
                    return self._summarize_plan(
                        plan_id,
                        budget,
                        paused_reason="BLOCKED_OR_CONFLICTED",
                        details={"blocked_or_conflicted": blocked_or_conflicted},
                    )

                # Step 3: Full write preflight
                try:
                    folder_id, preflight_info = await self._preflight(
                        plan, for_reconcile_only=False, expected_mode=expected_mode
                    )
                except AuthorizationRequiredError as exc:
                    return self._summarize_plan(
                        plan_id,
                        budget,
                        paused_reason="AUTHORIZATION_REQUIRED",
                        details={"error": redact_secrets(str(exc))},
                    )
                except RateLimitError as exc:
                    delay, _ = self.adapter.scheduler.record_rate_limit(
                        retry_after_seconds=exc.retry_after_seconds
                    )
                    return self._summarize_plan(
                        plan_id,
                        budget,
                        paused_reason="RATE_LIMITED",
                        details={"retry_after": delay, "error": redact_secrets(str(exc))},
                    )
                except (
                    AccountMismatchError,
                    SchemaDriftError,
                    ApprovalRequiredError,
                    PrivacyViolationError,
                ):
                    raise

                self._set_plan_status(plan_id, PlanStatus.EXECUTING)

                # Step 4: Resume ONLY pre-write paused/approved ops -> READY;
                # post-write PAUSED_VERIFICATION_* ops resume strictly to AWAITING_VERIFICATION (Audit R1)!
                for op in self.journal.list_ops(plan_id):
                    st = OperationState(str(op["state"]))
                    op_id = str(op["op_id"])
                    if st in (
                        OperationState.PAUSED_VERIFICATION_AUTH,
                        OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
                    ):
                        self.journal.transition(
                            op_id,
                            OperationState.AWAITING_VERIFICATION,
                            detail={"event": "resumed_verification_only"},
                        )
                    elif st in (
                        OperationState.APPROVED,
                        OperationState.PAUSED_AUTHORIZATION,
                        OperationState.PAUSED_RATE_LIMIT,
                        OperationState.RETRY_WAIT,
                    ):
                        # Defense-in-depth (Audit R1): refuse to re-dispatch any op that already holds a remote_id!
                        if op.get("remote_id") is not None:
                            self.journal.transition(
                                op_id,
                                OperationState.BLOCKED,
                                error_class=ErrorClass.POTENTIALLY_COMMITTED_WRITE,
                                error_message="Defense-in-depth block: op has remote_id and cannot re-enter READY.",
                            )
                            return self._summarize_plan(plan_id, budget, paused_reason="BLOCKED")
                        self.journal.transition(
                            op_id, OperationState.READY, detail={"event": "scheduled"}
                        )

                # Step 5: Execute in checkpointed batches
                last_batch: int | None = None
                for op in self.journal.list_ops(plan_id):
                    if self._shutdown_requested:
                        return self._summarize_plan(
                            plan_id,
                            budget,
                            paused_reason="SHUTDOWN_REQUESTED",
                            details={"preflight": preflight_info},
                        )

                    op_id = str(op["op_id"])
                    op = self.journal.get_op(op_id)
                    st = OperationState(str(op["state"]))
                    if is_terminal(st):
                        continue
                    if is_blocking(st):
                        return self._summarize_plan(plan_id, budget, paused_reason=st.value)

                    batch_num = int(op["batch_num"])
                    if last_batch is not None and batch_num != last_batch:
                        self._fire_fault("between_batches", op_id)
                    last_batch = batch_num

                    # Resume verification-only ops without re-dispatching writes (and propagate folder_id!)
                    if st in (OperationState.ACKNOWLEDGED, OperationState.AWAITING_VERIFICATION):
                        try:
                            ok = await self._reconcile_single_op(
                                op, folder_id=folder_id, budget=budget
                            )
                        except AuthorizationRequiredError as exc:
                            live_st = OperationState(str(self.journal.get_op(op_id)["state"]))
                            if live_st == OperationState.AWAITING_VERIFICATION:
                                self.journal.transition(
                                    op_id,
                                    OperationState.PAUSED_VERIFICATION_AUTH,
                                    error_class=ErrorClass.AUTHENTICATION_ERROR,
                                    error_message=str(exc),
                                )
                            return self._summarize_plan(
                                plan_id,
                                budget,
                                paused_reason="AUTHORIZATION_REQUIRED",
                                details={"error": redact_secrets(str(exc))},
                            )
                        except RateLimitError as exc:
                            delay, _ = self.adapter.scheduler.record_rate_limit(
                                retry_after_seconds=exc.retry_after_seconds
                            )
                            live_st = OperationState(str(self.journal.get_op(op_id)["state"]))
                            if live_st == OperationState.AWAITING_VERIFICATION:
                                self.journal.transition(
                                    op_id,
                                    OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
                                    error_class=ErrorClass.RATE_LIMIT_ERROR,
                                    error_message=str(exc),
                                )
                            return self._summarize_plan(
                                plan_id,
                                budget,
                                paused_reason="RATE_LIMITED",
                                details={"retry_after": delay, "error": redact_secrets(str(exc))},
                            )
                        except StreamMemoryError as exc:
                            return self._summarize_plan(
                                plan_id,
                                budget,
                                paused_reason="READ_TRANSIENT",
                                details={"op_id": op_id, "error": redact_secrets(str(exc))},
                            )
                        if not ok:
                            return self._summarize_plan(
                                plan_id, budget, paused_reason="VERIFICATION_FAILED"
                            )
                        if str(op["op_type"]) == OperationType.RESOLVE_OR_CREATE_FOLDER.value:
                            refreshed = self.journal.get_op(op_id)
                            if refreshed.get("remote_id"):
                                folder_id = str(refreshed["remote_id"])
                                self._update_plan_folder_id(plan_id, folder_id)
                        continue

                    op_type = OperationType(str(op["op_type"]))

                    # Audit R9: If RESOLVE_OR_CREATE_FOLDER sees folder_id already unambiguously resolved
                    # at preflight, adopt & verify it WITHOUT calling create_folder!
                    if op_type == OperationType.RESOLVE_OR_CREATE_FOLDER and folder_id is not None:
                        self.journal.transition(
                            op_id, OperationState.REQUEST_PREPARED, target_folder_id=folder_id
                        )
                        self.journal.transition(
                            op_id, OperationState.REQUEST_IN_FLIGHT, target_folder_id=folder_id
                        )
                        self.journal.transition(
                            op_id,
                            OperationState.ACKNOWLEDGED,
                            remote_id=folder_id,
                            target_folder_id=folder_id,
                            detail={"adopted_preflight_folder": True},
                        )
                        ok = await self._reconcile_single_op(
                            self.journal.get_op(op_id), folder_id=folder_id, budget=budget
                        )
                        if not ok:
                            return self._summarize_plan(plan_id, budget, paused_reason="CONFLICTED")
                        continue

                    # Section 13 hard rule: Briefing applies ONLY after all Log ops are VERIFIED!
                    if op_type == OperationType.SET_BRIEFING:
                        unverified_logs = [
                            str(o["op_id"])
                            for o in self.journal.list_ops(plan_id)
                            if str(o["op_type"])
                            in (OperationType.CREATE_LOG.value, OperationType.UPDATE_LOG.value)
                            and OperationState(str(o["state"])) != OperationState.VERIFIED
                        ]
                        if unverified_logs:
                            self.journal.transition(
                                op_id,
                                OperationState.BLOCKED,
                                error_class=ErrorClass.VALIDATION_PERMANENT,
                                error_message="Refusing to apply briefing while memory Log operations remain unverified.",
                            )
                            return self._summarize_plan(
                                plan_id, budget, paused_reason="UNVERIFIED_LOGS_BEFORE_BRIEFING"
                            )

                    res_status, new_folder_id = await self._execute_single_op(
                        op, folder_id=folder_id, budget=budget
                    )
                    if new_folder_id:
                        folder_id = new_folder_id
                        self._update_plan_folder_id(plan_id, folder_id)

                    if res_status != "VERIFIED":
                        return self._summarize_plan(
                            plan_id,
                            budget,
                            paused_reason=res_status,
                            details={"stopped_at_op": op_id, "preflight": preflight_info},
                        )

                    if budget.unresolved_operations >= budget.budget.max_unresolved_operations:
                        return self._summarize_plan(
                            plan_id,
                            budget,
                            paused_reason="UNCERTAIN_REMOTE_OUTCOME",
                            details={"stopped_at_op": op_id},
                        )

                return self._summarize_plan(
                    plan_id,
                    budget,
                    details={"preflight": preflight_info, "crash_recovery": crash_rec},
                )
        finally:
            if install_signal_handlers:
                if old_sigint is not None:
                    signal.signal(signal.SIGINT, old_sigint)
                if old_sigterm is not None:
                    signal.signal(signal.SIGTERM, old_sigterm)

    async def _execute_single_op(
        self,
        op: dict[str, Any],
        *,
        folder_id: str | None,
        budget: BudgetTracker,
    ) -> tuple[str, str | None]:
        """Durably journal, dispatch, and verify one mutating operation."""
        op_id = str(op["op_id"])
        plan_id = str(op["plan_id"])
        op_type = OperationType(str(op["op_type"]))
        payload = op["payload"]
        max_retries = budget.budget.max_retries_per_op

        for retry_idx in range(max_retries + 1):
            if self._shutdown_requested:
                return "SHUTDOWN_REQUESTED", None

            cur = self.journal.get_op(op_id)
            cur_st = OperationState(str(cur["state"]))
            if cur_st == OperationState.RETRY_WAIT:
                self.journal.transition(op_id, OperationState.READY, detail={"retry": retry_idx})

            try:
                budget.consume_write()
            except StreamMemoryError:
                return "BUDGET_EXHAUSTED", None

            self._fire_fault("before_journal_persist", op_id)

            # Invariant 4: Durable pre-write journal BEFORE touching network!
            self.journal.transition(
                op_id,
                OperationState.REQUEST_PREPARED,
                target_folder_id=folder_id,
                detail={"attempt": retry_idx + 1},
            )
            self._fire_fault("after_journal_persist", op_id)

            # Persist REQUEST_IN_FLIGHT BEFORE invoking the HTTP call!
            self.journal.transition(
                op_id,
                OperationState.REQUEST_IN_FLIGHT,
                increment_attempt=True,
                request_started=True,
                detail={"dispatched": True},
            )
            self._fire_fault("before_dispatch", op_id)

            try:
                remote_id: str | None = None
                remote_ts: int | None = None
                resolved_folder_id: str | None = None
                ack_meta: dict[str, Any] = {}

                if op_type == OperationType.RESOLVE_OR_CREATE_FOLDER:
                    folder = await self.adapter.create_folder(str(payload["name"]))
                    remote_id = folder.folder_id
                    remote_ts = folder.last_update_ts
                    resolved_folder_id = folder.folder_id
                    ack_meta = {"folder_id": folder.folder_id, "name": folder.name}
                elif op_type == OperationType.CREATE_LOG:
                    created = await self.adapter.create_log(
                        title=str(payload["title"]),
                        body=str(payload["body"]),
                        folder_id=folder_id,
                        idempotency_key=op_id,
                    )
                    remote_id = created.artifact_id
                    remote_ts = created.last_update_ts
                    ack_meta = {
                        "remote_id": created.artifact_id,
                        "search_index_status": created.search_index_status,
                    }
                elif op_type == OperationType.UPDATE_LOG:
                    updated = await self.adapter.update_log(
                        artifact_id=str(payload["remote_id"]),
                        title=str(payload["title"]),
                        body=str(payload["body"]),
                        expected_last_update_ts=payload.get("expected_last_update_ts"),
                    )
                    remote_id = updated.artifact_id
                    remote_ts = updated.last_update_ts
                    ack_meta = {"remote_id": updated.artifact_id}
                elif op_type == OperationType.UPDATE_FOLDER_INSTRUCTION:
                    if not folder_id:
                        raise StreamMemoryError(
                            "Missing target folder_id for UPDATE_FOLDER_INSTRUCTION",
                            error_class=ErrorClass.CONFIRMED_REJECTED_WRITE,
                            exit_code=ExitCode.VALIDATION_ERROR,
                        )
                    updated_f = await self.adapter.update_folder_instruction(
                        folder_id,
                        str(payload["instruction"]),
                        expected_last_update_ts=payload.get("expected_last_update_ts"),
                    )
                    remote_id = updated_f.folder_id
                    remote_ts = updated_f.last_update_ts
                    ack_meta = {"folder_id": updated_f.folder_id}
                elif op_type == OperationType.SET_BRIEFING:
                    br = await self.adapter.set_briefing(str(payload["body"]))
                    ack_meta = {"briefing_len": len(br.body)}
                else:
                    raise CapabilityUnsupportedError(
                        f"Operation type {op_type.value} cannot be auto-executed"
                    )

            except AuthorizationRequiredError as exc:
                self.journal.transition(
                    op_id,
                    OperationState.PAUSED_AUTHORIZATION,
                    error_class=ErrorClass.AUTHENTICATION_ERROR,
                    error_message=str(exc),
                    recovery_requirement="Renew OAuth via `stream-memory auth connect`, then run `reconcile` and `resume`.",
                )
                return "AUTHORIZATION_REQUIRED", None

            except RateLimitError as exc:
                delay, should_pause = self.adapter.scheduler.record_rate_limit(
                    retry_after_seconds=exc.retry_after_seconds
                )
                budget.total_retries += 1
                if should_pause or retry_idx >= max_retries or budget.record_error():
                    self.journal.transition(
                        op_id,
                        OperationState.PAUSED_RATE_LIMIT,
                        error_class=ErrorClass.RATE_LIMIT_ERROR,
                        error_message=str(exc),
                        recovery_requirement=f"Wait at least {delay:.1f}s and run `stream-memory resume`.",
                    )
                    return "RATE_LIMITED", None
                self.journal.transition(
                    op_id,
                    OperationState.RETRY_WAIT,
                    error_class=ErrorClass.RATE_LIMIT_ERROR,
                    error_message=str(exc),
                    detail={"retry_delay_s": delay},
                )
                await self.adapter.scheduler.clock.sleep(delay)
                continue

            except AmbiguousWriteError as exc:
                budget.unresolved_operations += 1
                with self.db.transaction():
                    self.journal.transition(
                        op_id,
                        OperationState.UNCERTAIN_REMOTE_OUTCOME,
                        error_class=ErrorClass.POTENTIALLY_COMMITTED_WRITE,
                        error_message=str(exc),
                        recovery_requirement="Run `stream-memory reconcile` to inspect remote evidence before resuming.",
                    )
                    rec_lid = str(payload.get("logical_id", ""))
                    if rec_lid and self.registry.get_record(rec_lid) is not None:
                        self.registry.mark_sync_status(rec_lid, RemoteSyncStatus.UNCERTAIN)
                return "UNCERTAIN_REMOTE_OUTCOME", None

            except CapabilityUnsupportedError as exc:
                self.journal.transition(
                    op_id,
                    OperationState.FAILED_CONFIRMED,
                    error_class=ErrorClass.UNSUPPORTED_CAPABILITY,
                    error_message=str(exc),
                )
                return "FAILED_CONFIRMED", None

            except StreamMemoryError as exc:
                if exc.error_class == ErrorClass.CONFLICT_ERROR:
                    self.journal.transition(
                        op_id,
                        OperationState.CONFLICTED,
                        error_class=ErrorClass.CONFLICT_ERROR,
                        error_message=str(exc),
                    )
                    return "CONFLICTED", None
                if exc.error_class in (
                    ErrorClass.CONFIRMED_REJECTED_WRITE,
                    ErrorClass.VALIDATION_PERMANENT,
                ):
                    self.journal.transition(
                        op_id,
                        OperationState.FAILED_CONFIRMED,
                        error_class=exc.error_class,
                        error_message=str(exc),
                    )
                    return "FAILED_CONFIRMED", None
                budget.unresolved_operations += 1
                self.journal.transition(
                    op_id,
                    OperationState.UNCERTAIN_REMOTE_OUTCOME,
                    error_class=ErrorClass.UNKNOWN_ERROR,
                    error_message=str(exc),
                )
                return "UNCERTAIN_REMOTE_OUTCOME", None

            # Server acknowledged! Persist ACK + folder_id atomically (Audit R9)
            self._fire_fault("after_ack", op_id)
            self._fire_fault("before_id_persist", op_id)
            with self.db.transaction():
                self.journal.transition(
                    op_id,
                    OperationState.ACKNOWLEDGED,
                    response_received=True,
                    response_status="ok",
                    remote_id=remote_id,
                    remote_last_update_ts=remote_ts,
                    target_folder_id=resolved_folder_id or folder_id,
                    detail=ack_meta,
                )
                if resolved_folder_id:
                    self._update_plan_folder_id(plan_id, resolved_folder_id)
            budget.record_success()

            # Explicit Postcondition Verification!
            updated_op = self.journal.get_op(op_id)
            effective_folder = resolved_folder_id or folder_id
            try:
                verified = await self._reconcile_single_op(
                    updated_op, folder_id=effective_folder, budget=budget
                )
            except AuthorizationRequiredError as exc:
                # Post-write auth failure -> PAUSED_VERIFICATION_AUTH (NEVER re-dispatches write!)
                self.journal.transition(
                    op_id,
                    OperationState.PAUSED_VERIFICATION_AUTH,
                    error_class=ErrorClass.AUTHENTICATION_ERROR,
                    error_message=str(exc),
                )
                return "AUTHORIZATION_REQUIRED", resolved_folder_id
            except RateLimitError as exc:
                self.adapter.scheduler.record_rate_limit(
                    retry_after_seconds=exc.retry_after_seconds
                )
                # Post-write 429 -> PAUSED_VERIFICATION_RATE_LIMIT (NEVER re-dispatches write!)
                self.journal.transition(
                    op_id,
                    OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
                    error_class=ErrorClass.RATE_LIMIT_ERROR,
                    error_message=str(exc),
                )
                return "RATE_LIMITED", resolved_folder_id
            except StreamMemoryError:
                return "READ_TRANSIENT", resolved_folder_id

            if not verified:
                final_st = str(self.journal.get_op(op_id)["state"])
                return final_st, resolved_folder_id
            return "VERIFIED", resolved_folder_id

        return "RATE_LIMITED", None


def _match_log_candidates(
    candidates: list[RemoteLog],
    *,
    expected_norm_hash: str,
    expected_title: str,
    folder_id: str | None,
    claimed_ids: set[str],
) -> tuple[list[RemoteLog], list[RemoteLog]]:
    """Separate unambiguous exact-hash matches from title-colliding conflicts."""
    exact_matches: list[RemoteLog] = []
    title_conflicts: list[RemoteLog] = []
    for rl in candidates:
        if not rl.artifact_id or rl.artifact_id in claimed_ids:
            continue
        if folder_id and rl.folder_id and rl.folder_id != folder_id:
            continue
        rl_title = normalize_remote_text(rl.title)
        rl_hash = canonical_json_hash({"title": rl_title, "body": normalize_remote_text(rl.body)})
        if rl_hash == expected_norm_hash:
            if rl.created_via_mcp is False:
                title_conflicts.append(rl)
            else:
                exact_matches.append(rl)
        elif rl_title == expected_title:
            title_conflicts.append(rl)
    return exact_matches, title_conflicts
