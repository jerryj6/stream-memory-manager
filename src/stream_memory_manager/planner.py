"""Remote-state observer, diff engine, immutable plan generator, and approval gate (Invariant 1)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from stream_memory_manager.auth import AccountBindingManager
from stream_memory_manager.capabilities import DiscoveredCapabilities
from stream_memory_manager.compiler import (
    COMPILER_VERSION,
    SANDBAR_FOLDER_NAME_LIMIT,
    load_compiled_artifacts,
    normalize_remote_text,
    validate_log_payload,
)
from stream_memory_manager.db import Database
from stream_memory_manager.locking import AccountWriterLock
from stream_memory_manager.mcp_adapter import (
    RemoteBriefing,
    RemoteFolder,
    RemoteLog,
    SandbarMCPAdapter,
)
from stream_memory_manager.models import (
    ApprovalRequiredError,
    CompiledArtifact,
    ErrorClass,
    ExecutionMode,
    ExitCode,
    OperationState,
    OperationType,
    PlanStatus,
    PrivacyViolationError,
    RequestBudget,
    StreamMemoryError,
    utc_now_iso,
)
from stream_memory_manager.privacy import assert_payload_safe, assert_record_exportable
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import canonical_account_scope, canonical_json_hash
from stream_memory_manager.state_machine import PRE_WRITE_CANCELLABLE_STATES, validate_transition


@dataclass
class ObservedRemoteState:
    folders: list[RemoteFolder] = field(default_factory=list)
    memory_folder_matches: list[RemoteFolder] = field(default_factory=list)
    existing_memory_logs: list[RemoteLog] = field(default_factory=list)
    existing_briefing: RemoteBriefing | None = None
    observed_account_id: str | None = None
    account_id_verified: bool = False
    observed_issuer: str | None = None
    is_offline_assumption: bool = False


async def observe_remote_state(
    adapter: SandbarMCPAdapter,
    *,
    target_folder_name: str = "Memory",
) -> ObservedRemoteState:
    """Strictly read-only inspection of current Sandbar state."""
    caps = adapter.capabilities
    if caps is None:
        caps = await adapter.discover_capabilities()

    acct_id, acct_verified, issuer = await adapter.get_account_identity()
    folders = await adapter.list_folders() if caps.supports_list_folders else []
    matches = [f for f in folders if f.name == target_folder_name]

    existing_logs: list[RemoteLog] = []
    if len(matches) == 1 and caps.supports_list_artifacts:
        listed = await adapter.list_artifacts(folder_id=matches[0].folder_id)
        if caps.supports_get_artifact:
            for rl in listed:
                if rl.artifact_id and (not rl.body.strip() or not rl.title.strip()):
                    full = await adapter.get_artifact(rl.artifact_id)
                    existing_logs.append(full if full is not None else rl)
                else:
                    existing_logs.append(rl)
        else:
            existing_logs = listed

    briefing = await adapter.get_briefing() if caps.supports_get_briefing else None

    return ObservedRemoteState(
        folders=folders,
        memory_folder_matches=matches,
        existing_memory_logs=existing_logs,
        existing_briefing=briefing,
        observed_account_id=acct_id,
        account_id_verified=acct_verified,
        observed_issuer=issuer,
        is_offline_assumption=False,
    )


class ImportPlanner:
    """Builds immutable, deterministically hashed import plans and enforces explicit approval."""

    def __init__(self, db: Database, registry: KnowledgeRegistry) -> None:
        self.db = db
        self.registry = registry

    def _lock_scope_for_plan(self, account_binding_hash: str) -> str:
        binding = AccountBindingManager(self.db).get_binding(account_binding_hash)
        if binding is None:
            return account_binding_hash
        return canonical_account_scope(
            server_url=str(binding["server_url"]),
            account_id=binding.get("account_id"),
            profile_name=str(binding["profile_name"]),
        )

    def build_plan(
        self,
        *,
        mode: ExecutionMode,
        account_binding_hash: str,
        capabilities: DiscoveredCapabilities,
        remote_state: ObservedRemoteState,
        target_folder_name: str = "Memory",
        include_folder_instruction: bool = True,
        include_briefing: bool = False,
        budget: RequestBudget | None = None,
        artifacts_override: list[CompiledArtifact] | None = None,
    ) -> dict[str, Any]:
        """Compute exact diff between approved compiled state and observed remote state."""
        if not target_folder_name or len(target_folder_name) > SANDBAR_FOLDER_NAME_LIMIT:
            raise StreamMemoryError(
                f"Target folder name {target_folder_name!r} invalid (1..{SANDBAR_FOLDER_NAME_LIMIT} chars)",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )

        if len(remote_state.memory_folder_matches) > 1:
            raise StreamMemoryError(
                f"Ambiguous remote state: found {len(remote_state.memory_folder_matches)} folders "
                f"named {target_folder_name!r}; cannot establish unambiguous folder identity.",
                error_class=ErrorClass.CONFLICT_ERROR,
                exit_code=ExitCode.BLOCKED_CONFLICT,
                details={
                    "matching_folder_ids": [f.folder_id for f in remote_state.memory_folder_matches]
                },
            )

        artifacts = (
            artifacts_override
            if artifacts_override is not None
            else load_compiled_artifacts(self.registry)
        )
        if not artifacts:
            raise StreamMemoryError(
                "No compiled artifacts available. Run `stream-memory compile` first.",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )

        # Re-verify privacy, length, and revision freshness on every artifact (Audit R13)
        for art in artifacts:
            assert_payload_safe(art.title, art.body, label=art.artifact_key)
            if art.artifact_kind == "log":
                validate_log_payload(art.title, art.body)
                if art.logical_id != "core_knowledge_index":
                    rec = self.registry.get_record(art.logical_id)
                    if rec is None:
                        raise PrivacyViolationError(
                            f"Compiled artifact {art.artifact_key} references missing record {art.logical_id!r}."
                        )
                    if int(rec["current_revision"]) != art.revision_number:
                        raise PrivacyViolationError(
                            f"Compiled artifact {art.artifact_key} is stale (rev {art.revision_number} != current {rec['current_revision']}); recompile first."
                        )
                    assert_record_exportable(rec)

        effective_budget = budget or RequestBudget()
        existing_folder = (
            remote_state.memory_folder_matches[0]
            if len(remote_state.memory_folder_matches) == 1
            else None
        )
        target_folder_id = existing_folder.folder_id if existing_folder else None

        # True ONLY when we did not (or could not) enumerate the remote Memory folder (Audit R5!)
        remote_listing_unavailable = remote_state.is_offline_assumption or (
            existing_folder is not None and not capabilities.supports_list_artifacts
        )

        remote_by_id = {
            rl.artifact_id: rl for rl in remote_state.existing_memory_logs if rl.artifact_id
        }
        remote_by_title: dict[str, list[RemoteLog]] = {}
        for rl in remote_state.existing_memory_logs:
            remote_by_title.setdefault(normalize_remote_text(rl.title), []).append(rl)

        planned_ops: list[dict[str, Any]] = []
        skipped_unchanged: list[str] = []
        manual_actions: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []
        assumptions: list[str] = []

        if remote_state.is_offline_assumption:
            assumptions.append(
                "Remote state was NOT queried (offline dry-run assumption); live preflight required."
            )
        if not capabilities.supports_update_log:
            assumptions.append(
                "Remote Log editing is unavailable; updates to verified Logs require manual replacement."
            )
        assumptions.append(
            "Remote deletion is unavailable via official Sandbar MCP; created Logs require manual deletion in Stream app."
        )
        if not capabilities.supports_idempotency_key:
            assumptions.append(
                "Server does not advertise idempotency keys for Log creation; ambiguous commits will reconcile or block."
            )

        # 1. Folder resolution or creation
        if existing_folder is None:
            if not capabilities.supports_create_folder:
                raise StreamMemoryError(
                    "Target folder does not exist and server does not advertise create_folder.",
                    error_class=ErrorClass.UNSUPPORTED_CAPABILITY,
                    exit_code=ExitCode.BLOCKED_CONFLICT,
                )
            folder_payload = {"name": target_folder_name}
            planned_ops.append(
                {
                    "logical_id": "meta_memory_folder",
                    "revision_number": 1,
                    "op_type": OperationType.RESOLVE_OR_CREATE_FOLDER.value,
                    "payload": folder_payload,
                    "payload_hash": canonical_json_hash(folder_payload),
                    "normalized_payload_hash": canonical_json_hash({"name": target_folder_name}),
                    "initial_state": OperationState.PLANNED.value,
                }
            )

        # 2. Log operations in deterministic compiler order — strictly account-scoped by artifact_key! (Audit R5)
        log_artifacts = [a for a in artifacts if a.artifact_kind == "log"]
        compiled_keys = {a.artifact_key for a in log_artifacts}

        # Detect shrunken multi-part records: previously verified part keys (e.g. rec:p2) now absent from compiled_keys!
        prev_verified_rows = self.db.conn.execute(
            """
            SELECT logical_id AS artifact_key, remote_id, normalized_payload_hash, remote_last_update_ts
            FROM operations
            WHERE op_type IN ('CREATE_LOG', 'UPDATE_LOG')
              AND state = 'VERIFIED' AND account_binding_hash = ?
            ORDER BY updated_at DESC;
            """,
            (account_binding_hash,),
        ).fetchall()
        latest_verified_by_key: dict[str, dict[str, Any]] = {}
        for row in prev_verified_rows:
            akey = str(row["artifact_key"])
            if akey not in latest_verified_by_key:
                latest_verified_by_key[akey] = dict(row)

        for art in log_artifacts:
            prev_ver = latest_verified_by_key.get(art.artifact_key)
            known_remote_id = (
                str(prev_ver["remote_id"]) if prev_ver and prev_ver.get("remote_id") else None
            )

            # Determine whether `known_remote_id` is actually still present on the live remote server!
            exists_remotely = bool(
                known_remote_id and (remote_listing_unavailable or known_remote_id in remote_by_id)
            )

            if exists_remotely and known_remote_id is not None:
                remote_match = remote_by_id.get(known_remote_id)
                if remote_match is not None:
                    remote_norm_hash = canonical_json_hash(
                        {
                            "title": normalize_remote_text(remote_match.title),
                            "body": normalize_remote_text(remote_match.body),
                        }
                    )
                    if remote_norm_hash == art.normalized_payload_hash:
                        skipped_unchanged.append(art.artifact_key)
                        continue
                elif (
                    prev_ver is not None
                    and str(prev_ver["normalized_payload_hash"]) == art.normalized_payload_hash
                ):
                    skipped_unchanged.append(art.artifact_key)
                    continue

                if capabilities.supports_update_log:
                    update_payload = {
                        "artifact_key": art.artifact_key,
                        "logical_id": art.logical_id,
                        "revision_number": art.revision_number,
                        "remote_id": known_remote_id,
                        "title": art.title,
                        "body": art.body,
                        "expected_last_update_ts": (
                            remote_match.last_update_ts
                            if remote_match
                            else (
                                int(prev_ver["remote_last_update_ts"])
                                if prev_ver and prev_ver.get("remote_last_update_ts") is not None
                                else None
                            )
                        ),
                    }
                    planned_ops.append(
                        {
                            "logical_id": art.artifact_key,
                            "revision_number": art.revision_number,
                            "op_type": OperationType.UPDATE_LOG.value,
                            "payload": update_payload,
                            "payload_hash": canonical_json_hash(update_payload),
                            "normalized_payload_hash": art.normalized_payload_hash,
                            "initial_state": OperationState.PLANNED.value,
                        }
                    )
                else:
                    manual_payload = {
                        "artifact_key": art.artifact_key,
                        "logical_id": art.logical_id,
                        "existing_remote_id": known_remote_id,
                        "title": art.title,
                        "reason": "Remote Log editing is unsupported; replace or remove obsolete Log in Stream app before re-importing.",
                    }
                    manual_actions.append(manual_payload)
                    planned_ops.append(
                        {
                            "logical_id": art.artifact_key,
                            "revision_number": art.revision_number,
                            "op_type": OperationType.MANUAL_REPLACEMENT_REQUIRED.value,
                            "payload": manual_payload,
                            "payload_hash": canonical_json_hash(manual_payload),
                            "normalized_payload_hash": art.normalized_payload_hash,
                            "initial_state": OperationState.BLOCKED.value,
                        }
                    )
                continue

            # Check for colliding remote Log inside Memory folder (Section 12 & 17)
            norm_title = normalize_remote_text(art.title)
            title_collisions = remote_by_title.get(norm_title, [])
            if title_collisions:
                exact_mcp = [
                    rl
                    for rl in title_collisions
                    if canonical_json_hash(
                        {
                            "title": normalize_remote_text(rl.title),
                            "body": normalize_remote_text(rl.body),
                        }
                    )
                    == art.normalized_payload_hash
                    and rl.created_via_mcp is not False
                ]
                if len(exact_mcp) == 1:
                    skipped_unchanged.append(art.artifact_key)
                    continue
                conflicts.append(
                    {
                        "artifact_key": art.artifact_key,
                        "title": art.title,
                        "colliding_remote_ids": [rl.artifact_id for rl in title_collisions],
                        "reason": "Existing remote Log in Memory folder shares title with different content; refusing to overwrite or duplicate.",
                    }
                )
                create_payload = {
                    "artifact_key": art.artifact_key,
                    "logical_id": art.logical_id,
                    "revision_number": art.revision_number,
                    "title": art.title,
                    "body": art.body,
                    "folder_name": target_folder_name,
                }
                planned_ops.append(
                    {
                        "logical_id": art.artifact_key,
                        "revision_number": art.revision_number,
                        "op_type": OperationType.CREATE_LOG.value,
                        "payload": create_payload,
                        "payload_hash": canonical_json_hash(create_payload),
                        "normalized_payload_hash": art.normalized_payload_hash,
                        "initial_state": OperationState.CONFLICTED.value,
                    }
                )
                continue

            create_payload = {
                "artifact_key": art.artifact_key,
                "logical_id": art.logical_id,
                "revision_number": art.revision_number,
                "title": art.title,
                "body": art.body,
                "folder_name": target_folder_name,
            }
            planned_ops.append(
                {
                    "logical_id": art.artifact_key,
                    "revision_number": art.revision_number,
                    "op_type": OperationType.CREATE_LOG.value,
                    "payload": create_payload,
                    "payload_hash": canonical_json_hash(create_payload),
                    "normalized_payload_hash": art.normalized_payload_hash,
                    "initial_state": OperationState.PLANNED.value,
                }
            )

        # Emit MANUAL_DELETION_REQUIRED for orphaned split parts (e.g. record shrank from 2 parts to 1)
        compiled_logical_ids = {a.logical_id for a in log_artifacts}
        for old_akey, old_row in latest_verified_by_key.items():
            if old_akey in compiled_keys:
                continue
            base_lid = old_akey.rsplit(":p", 1)[0]
            old_rid = str(old_row["remote_id"]) if old_row.get("remote_id") else None
            if (
                base_lid in compiled_logical_ids
                and old_rid
                and (remote_listing_unavailable or old_rid in remote_by_id)
            ):
                del_payload = {
                    "artifact_key": old_akey,
                    "logical_id": base_lid,
                    "obsolete_remote_id": old_rid,
                    "reason": "Multi-part record shrank; obsolete remote part requires manual deletion in Stream app.",
                }
                manual_actions.append(del_payload)
                planned_ops.append(
                    {
                        "logical_id": old_akey,
                        "revision_number": 0,
                        "op_type": OperationType.MANUAL_DELETION_REQUIRED.value,
                        "payload": del_payload,
                        "payload_hash": canonical_json_hash(del_payload),
                        "normalized_payload_hash": canonical_json_hash(del_payload),
                        "initial_state": OperationState.BLOCKED.value,
                    }
                )

        # 3. Folder instruction update
        folder_instr_arts = [a for a in artifacts if a.artifact_kind == "folder_instruction"]
        if include_folder_instruction and folder_instr_arts and capabilities.supports_update_folder:
            fi = folder_instr_arts[0]
            if len(fi.body) > capabilities.folder_instruction_max_chars:
                raise StreamMemoryError(
                    f"Folder instruction ({len(fi.body)} chars) exceeds server limit ({capabilities.folder_instruction_max_chars})",
                    error_class=ErrorClass.VALIDATION_PERMANENT,
                    exit_code=ExitCode.VALIDATION_ERROR,
                )
            existing_instr = (
                normalize_remote_text(existing_folder.instruction or "") if existing_folder else ""
            )
            if existing_instr != normalize_remote_text(fi.body):
                fi_payload = {
                    "folder_name": target_folder_name,
                    "instruction": fi.body,
                    "previous_instruction": existing_folder.instruction
                    if existing_folder
                    else None,
                    "expected_last_update_ts": (
                        existing_folder.last_update_ts if existing_folder else None
                    ),
                }
                planned_ops.append(
                    {
                        "logical_id": fi.artifact_key,
                        "revision_number": fi.revision_number,
                        "op_type": OperationType.UPDATE_FOLDER_INSTRUCTION.value,
                        "payload": fi_payload,
                        "payload_hash": canonical_json_hash(fi_payload),
                        "normalized_payload_hash": fi.normalized_payload_hash,
                        "initial_state": OperationState.PLANNED.value,
                    }
                )

        # 4. Briefing update — FIXED guard (Audit R6):
        # Omit unless BOTH set_briefing AND get_briefing are supported AND existing briefing is empty or managed!
        briefing_arts = [a for a in artifacts if a.artifact_kind == "briefing"]
        briefing_omitted_reason: str | None = None
        if include_briefing and briefing_arts:
            if not capabilities.supports_set_briefing:
                briefing_omitted_reason = (
                    "Server does not advertise a briefing write tool in confirmed schema."
                )
                assumptions.append(briefing_omitted_reason)
            elif not capabilities.supports_get_briefing:
                briefing_omitted_reason = "Server does not advertise get_briefing; omitting SET_BRIEFING to avoid clobbering unrelated context or failing verification."
                assumptions.append(briefing_omitted_reason)
            else:
                br = briefing_arts[0]
                existing_br_text = (
                    normalize_remote_text(remote_state.existing_briefing.body)
                    if remote_state.existing_briefing
                    else ""
                )
                if existing_br_text and "Memory folder" not in existing_br_text:
                    briefing_omitted_reason = "Existing remote briefing appears unrelated to Stream Memory Manager; omitting to avoid overwriting user context."
                    assumptions.append(briefing_omitted_reason)
                elif existing_br_text != normalize_remote_text(br.body):
                    br_payload = {
                        "body": br.body,
                        "previous_briefing": (
                            remote_state.existing_briefing.body
                            if remote_state.existing_briefing
                            else None
                        ),
                    }
                    planned_ops.append(
                        {
                            "logical_id": br.artifact_key,
                            "revision_number": br.revision_number,
                            "op_type": OperationType.SET_BRIEFING.value,
                            "payload": br_payload,
                            "payload_hash": canonical_json_hash(br_payload),
                            "normalized_payload_hash": br.normalized_payload_hash,
                            "initial_state": OperationState.PLANNED.value,
                        }
                    )

        mutating_count = sum(
            1
            for op in planned_ops
            if op["op_type"]
            not in (
                OperationType.MANUAL_REPLACEMENT_REQUIRED.value,
                OperationType.MANUAL_DELETION_REQUIRED.value,
            )
            and op["initial_state"] == OperationState.PLANNED.value
        )
        if mutating_count > effective_budget.max_planned_writes:
            raise StreamMemoryError(
                f"Planned mutating operations ({mutating_count}) exceed configured max_planned_writes ({effective_budget.max_planned_writes})",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )

        # Deterministic immutable plan ID including FULL op payloads & budget (Audit R8)
        plan_identity_input = {
            "mode": mode.value,
            "account_binding_hash": account_binding_hash,
            "target_folder_name": target_folder_name,
            "target_folder_id": target_folder_id,
            "capability_fingerprint": capabilities.schema_fingerprint,
            "compiler_version": COMPILER_VERSION,
            "budget": effective_budget.model_dump(),
            "operations": [
                {
                    "seq": idx,
                    "logical_id": op["logical_id"],
                    "revision": op["revision_number"],
                    "op_type": op["op_type"],
                    "payload_hash": op["payload_hash"],
                    "initial_state": op["initial_state"],
                }
                for idx, op in enumerate(planned_ops, start=1)
            ],
        }
        base_plan_id = f"plan_{canonical_json_hash(plan_identity_input)[:20]}"

        summary = {
            "total_operations": len(planned_ops),
            "mutating_operations": mutating_count,
            "skipped_unchanged": len(skipped_unchanged),
            "manual_actions_required": len(manual_actions),
            "conflicts": conflicts,
            "briefing_omitted_reason": briefing_omitted_reason,
            "non_reversible_warning": "Sandbar MCP does not support deleting Logs or Folders; manual cleanup in Stream app is required to remove created items.",
            "operation_breakdown": _count_by_op_type(planned_ops),
        }

        now = utc_now_iso()
        with self.db.transaction() as conn:
            plan_id = base_plan_id
            existing_plan = conn.execute(
                "SELECT plan_id, status FROM plans WHERE plan_id = ?;", (plan_id,)
            ).fetchone()
            # Only reuse an existing plan if it is still DRAFT! Never reuse CANCELLED/INVALIDATED/APPROVED (Audit R8).
            if existing_plan is not None and str(existing_plan["status"]) == PlanStatus.DRAFT.value:
                return self.get_plan(plan_id)
            if existing_plan is not None:
                suffix = 2
                while conn.execute(
                    "SELECT 1 FROM plans WHERE plan_id = ?;", (f"{base_plan_id}_v{suffix}",)
                ).fetchone():
                    suffix += 1
                plan_id = f"{base_plan_id}_v{suffix}"

            conn.execute(
                """
                INSERT INTO plans (
                    plan_id, mode, account_binding_hash, target_folder_name, target_folder_id,
                    capability_fingerprint, compiler_version, status, budget_json,
                    assumptions_json, summary_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    plan_id,
                    mode.value,
                    account_binding_hash,
                    target_folder_name,
                    target_folder_id,
                    capabilities.schema_fingerprint,
                    COMPILER_VERSION,
                    PlanStatus.DRAFT.value,
                    effective_budget.model_dump_json(),
                    json.dumps(assumptions),
                    json.dumps(summary, sort_keys=True),
                    now,
                ),
            )
            for idx, op in enumerate(planned_ops, start=1):
                batch_num = ((idx - 1) // max(1, effective_budget.batch_size)) + 1
                op_id = f"{plan_id}:op{idx:04d}"
                conn.execute(
                    """
                    INSERT INTO operations (
                        op_id, plan_id, sequence_num, batch_num, logical_id, revision_number,
                        op_type, account_binding_hash, target_folder_id, payload_json,
                        payload_hash, normalized_payload_hash, state, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        op_id,
                        plan_id,
                        idx,
                        batch_num,
                        op["logical_id"],
                        op["revision_number"],
                        op["op_type"],
                        account_binding_hash,
                        target_folder_id,
                        json.dumps(op["payload"], sort_keys=True, ensure_ascii=False),
                        op["payload_hash"],
                        op["normalized_payload_hash"],
                        op["initial_state"],
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO operation_events (op_id, plan_id, from_state, to_state, detail_json, created_at)
                    VALUES (?, ?, NULL, ?, ?, ?);
                    """,
                    (
                        op_id,
                        plan_id,
                        op["initial_state"],
                        json.dumps({"event": "planned", "op_type": op["op_type"]}),
                        now,
                    ),
                )

        return self.get_plan(plan_id)

    def get_plan(self, plan_id: str) -> dict[str, Any]:
        row = self.db.conn.execute("SELECT * FROM plans WHERE plan_id = ?;", (plan_id,)).fetchone()
        if not row:
            raise StreamMemoryError(
                f"Plan not found: {plan_id}",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        ops = self.db.conn.execute(
            "SELECT * FROM operations WHERE plan_id = ? ORDER BY sequence_num ASC;", (plan_id,)
        ).fetchall()
        plan = dict(row)
        plan["budget"] = json.loads(str(plan.pop("budget_json")))
        plan["assumptions"] = json.loads(str(plan.pop("assumptions_json")))
        plan["summary"] = json.loads(str(plan.pop("summary_json")))
        plan["operations"] = [
            {
                **dict(o),
                "payload": json.loads(str(o["payload_json"])),
            }
            for o in ops
        ]
        return plan

    def list_plans(self) -> list[dict[str, Any]]:
        rows = self.db.conn.execute("SELECT * FROM plans ORDER BY created_at DESC;").fetchall()
        return [
            {
                **dict(r),
                "summary": json.loads(str(r["summary_json"])),
            }
            for r in rows
        ]

    def approve_plan(
        self,
        plan_id: str,
        *,
        actor: str = "user",
        note: str = "",
        lock_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Explicitly approve a DRAFT immutable plan_id under writer lock (Audit R4)."""
        plan_peek = self.get_plan(plan_id)
        l_dir = lock_dir or (self.db.db_path.parent / "locks")
        scope = self._lock_scope_for_plan(str(plan_peek["account_binding_hash"]))

        with AccountWriterLock(l_dir, scope):
            now = utc_now_iso()
            with self.db.transaction() as conn:
                row = conn.execute("SELECT * FROM plans WHERE plan_id = ?;", (plan_id,)).fetchone()
                if not row:
                    raise StreamMemoryError(f"Plan not found: {plan_id}")
                status = PlanStatus(str(row["status"]))
                if status != PlanStatus.DRAFT:
                    raise ApprovalRequiredError(
                        f"Only DRAFT plans can be approved (plan {plan_id} is currently {status.value})."
                    )
                conn.execute(
                    """
                    UPDATE plans
                    SET status = ?, approved_at = ?, approval_actor = ?, approval_note = ?
                    WHERE plan_id = ? AND status = ?;
                    """,
                    (PlanStatus.APPROVED.value, now, actor, note, plan_id, PlanStatus.DRAFT.value),
                )
                planned_ops = conn.execute(
                    "SELECT op_id FROM operations WHERE plan_id = ? AND state = ?;",
                    (plan_id, OperationState.PLANNED.value),
                ).fetchall()
                for op in planned_ops:
                    op_id = str(op["op_id"])
                    validate_transition(
                        OperationState.PLANNED, OperationState.APPROVED, op_id=op_id
                    )
                    conn.execute(
                        "UPDATE operations SET state = ?, updated_at = ? WHERE op_id = ? AND state = ?;",
                        (
                            OperationState.APPROVED.value,
                            now,
                            op_id,
                            OperationState.PLANNED.value,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO operation_events (op_id, plan_id, from_state, to_state, detail_json, created_at)
                        VALUES (?, ?, ?, ?, ?, ?);
                        """,
                        (
                            op_id,
                            plan_id,
                            OperationState.PLANNED.value,
                            OperationState.APPROVED.value,
                            json.dumps({"actor": actor, "note": note}),
                            now,
                        ),
                    )
        return self.get_plan(plan_id)

    def invalidate_plan(self, plan_id: str, reason: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE plans SET status = ?, invalidated_reason = ? WHERE plan_id = ?;",
                (PlanStatus.INVALIDATED.value, reason, plan_id),
            )

    def cancel_plan(
        self,
        plan_id: str,
        *,
        reason: str = "user_cancelled",
        lock_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Cancel not-yet-dispatched operations atomically under writer lock (Audit R4)."""
        plan_peek = self.get_plan(plan_id)
        l_dir = lock_dir or (self.db.db_path.parent / "locks")
        scope = self._lock_scope_for_plan(str(plan_peek["account_binding_hash"]))

        with AccountWriterLock(l_dir, scope):
            now = utc_now_iso()
            cancelled = 0
            already_dispatched = 0
            with self.db.transaction() as conn:
                # Re-read live op rows INSIDE BEGIN IMMEDIATE transaction (zero TOCTOU!)
                live_ops = conn.execute(
                    "SELECT op_id, state, request_started_at, remote_id FROM operations WHERE plan_id = ? ORDER BY sequence_num ASC;",
                    (plan_id,),
                ).fetchall()
                for op in live_ops:
                    op_id = str(op["op_id"])
                    st = OperationState(str(op["state"]))
                    # Defense-in-depth: never mark an op with a persisted remote_id as CANCELLED_BEFORE_WRITE!
                    if st in PRE_WRITE_CANCELLABLE_STATES and op["remote_id"] is None:
                        validate_transition(st, OperationState.CANCELLED_BEFORE_WRITE, op_id=op_id)
                        conn.execute(
                            "UPDATE operations SET state = ?, updated_at = ? WHERE op_id = ? AND state = ?;",
                            (
                                OperationState.CANCELLED_BEFORE_WRITE.value,
                                now,
                                op_id,
                                st.value,
                            ),
                        )
                        conn.execute(
                            """
                            INSERT INTO operation_events (op_id, plan_id, from_state, to_state, detail_json, created_at)
                            VALUES (?, ?, ?, ?, ?, ?);
                            """,
                            (
                                op_id,
                                plan_id,
                                st.value,
                                OperationState.CANCELLED_BEFORE_WRITE.value,
                                json.dumps({"reason": reason}),
                                now,
                            ),
                        )
                        cancelled += 1
                    elif st != OperationState.CANCELLED_BEFORE_WRITE:
                        already_dispatched += 1

                new_status = (
                    PlanStatus.CANCELLED.value
                    if already_dispatched == 0
                    else PlanStatus.PAUSED.value
                )
                conn.execute(
                    "UPDATE plans SET status = ? WHERE plan_id = ?;", (new_status, plan_id)
                )

        return {
            "plan_id": plan_id,
            "cancelled_before_write": cancelled,
            "already_dispatched_or_verified": already_dispatched,
            "warning": (
                "Already created remote Logs cannot be deleted via MCP; manual cleanup in Stream app is required."
                if already_dispatched > 0
                else "No remote writes occurred before cancellation."
            ),
        }


def _count_by_op_type(ops: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for op in ops:
        t = str(op["op_type"])
        counts[t] = counts.get(t, 0) + 1
    return counts
