"""Agent-ergonomic OBSERVE -> ORIENT machine-readable state snapshots and non-destructive doctor diagnostics."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Any

from stream_memory_manager.auth import SANDBAR_OFFICIAL_MCP_URL, AccountBindingManager
from stream_memory_manager.capabilities import CapabilityStore
from stream_memory_manager.db import Database
from stream_memory_manager.models import ExecutionMode, OperationState, PlanStatus
from stream_memory_manager.planner import ImportPlanner
from stream_memory_manager.rate_limit import AccountRateScheduler
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import canonical_account_scope


def compute_system_status(
    *,
    db: Database,
    mode: ExecutionMode = ExecutionMode.DRY_RUN,
    profile: str = "default",
    target_folder: str = "Memory",
) -> dict[str, Any]:
    """Produce a compact, machine-readable state snapshot so any agent immediately knows the next safe action."""
    registry = KnowledgeRegistry(db)
    planner = ImportPlanner(db, registry)
    cap_store = CapabilityStore(db)
    bindings = AccountBindingManager(db)

    all_records = registry.list_records()
    approved_eligible = [
        r
        for r in all_records
        if r["destination_eligible"] and str(r["inclusion_decision"]) == "APPROVED"
    ]
    pending_review = [
        r
        for r in all_records
        if str(r["inclusion_decision"]) == "PENDING_REVIEW" and r["destination_eligible"]
    ]
    excluded = [
        r
        for r in all_records
        if str(r["inclusion_decision"]) == "EXCLUDED" or not r["destination_eligible"]
    ]
    compiled_count = int(
        db.conn.execute(
            "SELECT COUNT(*) AS c FROM compiled_artifacts WHERE artifact_kind = 'log';"
        ).fetchone()["c"]
    )
    open_issues = registry.list_issues(status="OPEN")
    latest_binding = bindings.get_latest_for_profile(profile)
    latest_caps = cap_store.get_latest()

    plans = planner.list_plans()
    active_plan = plans[0] if plans else None
    active_plan_id = str(active_plan["plan_id"]) if active_plan else None
    active_plan_status = str(active_plan["status"]) if active_plan else None

    op_counts: dict[str, int] = {
        "verified": 0,
        "pending": 0,
        "uncertain": 0,
        "blocked": 0,
        "conflicted": 0,
        "paused_auth": 0,
        "paused_rate_limit": 0,
        "paused_ver_auth": 0,
        "paused_ver_rl": 0,
        "failed": 0,
        "cancelled": 0,
        "awaiting_verification": 0,
    }
    if active_plan_id:
        full_plan = planner.get_plan(active_plan_id)
        for op in full_plan["operations"]:
            st = OperationState(str(op["state"]))
            if st == OperationState.VERIFIED:
                op_counts["verified"] += 1
            elif st in (OperationState.UNCERTAIN_REMOTE_OUTCOME, OperationState.REQUEST_IN_FLIGHT):
                op_counts["uncertain"] += 1
            elif st == OperationState.BLOCKED:
                op_counts["blocked"] += 1
            elif st == OperationState.CONFLICTED:
                op_counts["conflicted"] += 1
            elif st == OperationState.PAUSED_AUTHORIZATION:
                op_counts["paused_auth"] += 1
            elif st == OperationState.PAUSED_RATE_LIMIT:
                op_counts["paused_rate_limit"] += 1
            elif st == OperationState.PAUSED_VERIFICATION_AUTH:
                op_counts["paused_ver_auth"] += 1
            elif st == OperationState.PAUSED_VERIFICATION_RATE_LIMIT:
                op_counts["paused_ver_rl"] += 1
            elif st == OperationState.FAILED_CONFIRMED:
                op_counts["failed"] += 1
            elif st == OperationState.CANCELLED_BEFORE_WRITE:
                op_counts["cancelled"] += 1
            elif st in (OperationState.AWAITING_VERIFICATION, OperationState.ACKNOWLEDGED):
                op_counts["awaiting_verification"] += 1
            else:
                op_counts["pending"] += 1

    blocked_reason: str | None = None
    remote_writes_allowed = False
    next_safe_action = "ingest"

    if len(all_records) == 0:
        blocked_reason = "NO_RECORDS_INGESTED"
        next_safe_action = "ingest <source_file>"
    elif op_counts["uncertain"] > 0:
        blocked_reason = "UNCERTAIN_REMOTE_OUTCOME"
        next_safe_action = f"reconcile --plan-id {active_plan_id}"
    elif op_counts["paused_auth"] > 0 or op_counts["paused_ver_auth"] > 0:
        blocked_reason = "PAUSED_AUTHORIZATION"
        next_safe_action = f"auth connect && reconcile --plan-id {active_plan_id}"
    elif op_counts["paused_ver_rl"] > 0:
        blocked_reason = "PAUSED_VERIFICATION_RATE_LIMIT"
        next_safe_action = f"reconcile --plan-id {active_plan_id}"
    elif op_counts["conflicted"] > 0 or op_counts["blocked"] > 0:
        blocked_reason = "CONFLICTED_OR_BLOCKED_OPERATIONS"
        next_safe_action = f"preview --plan-id {active_plan_id}"
    elif op_counts["failed"] > 0:
        blocked_reason = "FAILED_CONFIRMED"
        next_safe_action = f"preview --plan-id {active_plan_id} && plan"
    elif op_counts["awaiting_verification"] > 0:
        blocked_reason = "AWAITING_VERIFICATION"
        next_safe_action = f"verify --plan-id {active_plan_id}"
    elif compiled_count == 0:
        if len(approved_eligible) == 0:
            blocked_reason = "PRIVACY_REVIEW_REQUIRED"
            next_safe_action = "privacy-review"
        else:
            blocked_reason = "NOT_COMPILED"
            next_safe_action = "compile"
    elif active_plan is None:
        blocked_reason = "NO_PLAN_GENERATED"
        next_safe_action = "plan"
    elif active_plan_status == PlanStatus.DRAFT.value:
        blocked_reason = "APPROVAL_REQUIRED"
        next_safe_action = (
            f"preview --plan-id {active_plan_id} && approve --plan-id {active_plan_id}"
        )
    elif active_plan_status == PlanStatus.INVALIDATED.value:
        blocked_reason = "PLAN_INVALIDATED"
        next_safe_action = "plan"
    elif active_plan_status == PlanStatus.CANCELLED.value:
        blocked_reason = "PLAN_CANCELLED"
        next_safe_action = "plan"
    elif active_plan_status == PlanStatus.EXECUTING.value:
        blocked_reason = "PLAN_EXECUTING_OR_INTERRUPTED"
        next_safe_action = f"reconcile --plan-id {active_plan_id}"
    elif active_plan_status == PlanStatus.PARTIALLY_VERIFIED.value:
        blocked_reason = "PARTIALLY_VERIFIED"
        next_safe_action = f"verify --plan-id {active_plan_id}"
    elif active_plan_status == PlanStatus.BLOCKED.value:
        blocked_reason = "PLAN_BLOCKED"
        next_safe_action = f"reconcile --plan-id {active_plan_id}"
    elif active_plan_status == PlanStatus.COMPLETED.value:
        blocked_reason = None
        next_safe_action = "evaluate"
    elif active_plan_status in (PlanStatus.APPROVED.value, PlanStatus.PAUSED.value):
        if mode == ExecutionMode.DRY_RUN:
            blocked_reason = "DRY_RUN_MODE"
            next_safe_action = f"apply --plan-id {active_plan_id} --mode mock|live"
        elif latest_binding is None:
            blocked_reason = "ACCOUNT_NOT_BOUND"
            next_safe_action = "auth connect"
        else:
            remote_writes_allowed = True
            next_safe_action = f"apply --plan-id {active_plan_id} --mode {mode.value}"

    # Unified canonical account scope matching CLI & ExecutionEngine (Audit R10)
    acct_key = (
        canonical_account_scope(
            server_url=str(latest_binding["server_url"]),
            account_id=latest_binding.get("account_id"),
            profile_name=profile,
        )
        if latest_binding
        else canonical_account_scope(server_url=SANDBAR_OFFICIAL_MCP_URL, profile_name=profile)
    )
    rl_snap = AccountRateScheduler(db, acct_key).status_snapshot()

    return {
        "mode": mode.value,
        "account_verified": bool(latest_binding and latest_binding["account_id_verified"]),
        "account_binding_hash": latest_binding["binding_hash"] if latest_binding else None,
        "active_plan": active_plan_id,
        "active_plan_status": active_plan_status,
        "target_folder": target_folder,
        "canonical_records_total": len(all_records),
        "canonical_records_approved": len(approved_eligible),
        "canonical_records_pending_review": len(pending_review),
        "canonical_records_excluded": len(excluded),
        "compiled_logs_total": compiled_count,
        "records_total": sum(op_counts.values()),
        "records_verified": op_counts["verified"],
        "records_pending": op_counts["pending"] + op_counts["awaiting_verification"],
        "records_uncertain": op_counts["uncertain"],
        "records_blocked": op_counts["blocked"],
        "records_conflicted": op_counts["conflicted"],
        "records_failed": op_counts["failed"],
        "records_cancelled": op_counts["cancelled"],
        "open_issues_count": len(open_issues),
        "capability_fingerprint": latest_caps.schema_fingerprint[:16] if latest_caps else None,
        "remote_writes_allowed": remote_writes_allowed,
        "blocked_reason": blocked_reason,
        "next_safe_action": next_safe_action,
        "rate_limit": rl_snap,
    }


def _inspect_existing_locks_readonly(lock_dir: Path) -> list[dict[str, Any]]:
    """Probe existing writer_*.lock files without creating spurious files (Audit R10)."""
    active: list[dict[str, Any]] = []
    if not lock_dir.exists():
        return active
    for lp in sorted(lock_dir.glob("writer_*.lock")):
        if lp.is_symlink():
            continue
        try:
            fd = os.open(str(lp), os.O_RDONLY)
        except OSError:
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            except BlockingIOError:
                holder = None
                try:
                    raw = lp.read_text(encoding="utf-8").strip()
                    holder = json.loads(raw) if raw else None
                except Exception:
                    holder = None
                active.append({"lock_file": lp.name, "holder": holder})
        finally:
            os.close(fd)
    return active


def run_doctor(db: Database, *, data_dir: Path, profile: str = "default") -> dict[str, Any]:
    """Run local health, integrity, permissions, lock, and safety diagnostics without mutating state."""
    checks: list[dict[str, Any]] = []

    try:
        db.verify_integrity()
        checks.append(
            {
                "check": "sqlite_integrity",
                "status": "PASS",
                "detail": f"schema v{db.schema_version()}",
            }
        )
    except Exception as exc:
        checks.append({"check": "sqlite_integrity", "status": "FAIL", "detail": str(exc)})

    db_mode = oct(os.stat(db.db_path).st_mode & 0o777) if db.db_path.exists() else "missing"
    dir_mode = oct(os.stat(data_dir).st_mode & 0o777) if data_dir.exists() else "missing"
    perms_ok = db_mode in ("0o600", "missing") and dir_mode in ("0o700", "missing")
    checks.append(
        {
            "check": "filesystem_permissions",
            "status": "PASS" if perms_ok else "WARN",
            "detail": f"data_dir={dir_mode}, db={db_mode} (expected 0o700/0o600)",
        }
    )

    active_locks = _inspect_existing_locks_readonly(data_dir / "locks")
    checks.append(
        {
            "check": "writer_lock",
            "status": "WARN" if active_locks else "PASS",
            "detail": f"active_locks={len(active_locks)}, holders={active_locks}",
        }
    )

    registry = KnowledgeRegistry(db)
    crit = [i for i in registry.list_issues(status="OPEN") if i["severity"] in ("CRITICAL", "HIGH")]
    checks.append(
        {
            "check": "open_high_issues",
            "status": "WARN" if crit else "PASS",
            "detail": f"{len(crit)} open CRITICAL/HIGH issue(s)",
        }
    )

    caps = CapabilityStore(db).get_latest()
    checks.append(
        {
            "check": "capability_snapshot",
            "status": "PASS" if caps else "INFO",
            "detail": (
                f"fingerprint={caps.schema_fingerprint[:16]} protocol={caps.protocol_version}"
                if caps
                else "No live capability snapshot discovered yet (dry-run offline baseline available)."
            ),
        }
    )

    overall_ok = all(c["status"] != "FAIL" for c in checks)
    return {"healthy": overall_ok, "db_path": str(db.db_path), "profile": profile, "checks": checks}
