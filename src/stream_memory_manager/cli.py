"""Agent-ergonomic CLI (`stream-memory`) with strict --json mode, mode-to-endpoint isolation, and redacted output."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from stream_memory_manager.auth import (
    SANDBAR_OFFICIAL_MCP_URL,
    AccountBindingManager,
    SecureTokenStorage,
    revoke_and_disconnect,
    run_interactive_oauth_connect,
)
from stream_memory_manager.capabilities import (
    CapabilityStore,
    default_offline_documented_capabilities,
)
from stream_memory_manager.compiler import compile_memory, load_compiled_artifacts
from stream_memory_manager.consolidator import (
    analyze_corpus,
    apply_agent_dossiers,
    build_agent_consolidation_pack,
    merge_records,
)
from stream_memory_manager.db import Database, restore_backup
from stream_memory_manager.evaluator import (
    generate_native_evaluation_protocol,
    run_local_retrieval_evaluation,
)
from stream_memory_manager.executor import ExecutionEngine
from stream_memory_manager.exporter import export_bundle
from stream_memory_manager.harvesters import (
    build_web_extraction_kit,
    detect_local_sources,
    harvest_local_sources,
    parse_web_export_to_markdown,
)
from stream_memory_manager.ingestion import ingest_file
from stream_memory_manager.mcp_adapter import (
    DEFAULT_ARCHIVE_FOLDER_NAME,
    SandbarMCPAdapter,
    inspect_live_memory_state,
    quarantine_logs_to_archive,
)
from stream_memory_manager.models import (
    ErrorClass,
    ExecutionMode,
    ExitCode,
    InclusionDecision,
    PrivacyClassification,
    RequestBudget,
    StreamMemoryError,
)
from stream_memory_manager.planner import ImportPlanner, ObservedRemoteState, observe_remote_state
from stream_memory_manager.privacy import evaluate_registry_privacy
from stream_memory_manager.rate_limit import AccountRateScheduler
from stream_memory_manager.reconciliation import reconcile_registry
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import (
    canonical_account_scope,
    ensure_private_dir,
    redact_object,
    redact_secrets,
    validate_endpoint_url,
)
from stream_memory_manager.status import compute_system_status, run_doctor

app = typer.Typer(
    name="stream-memory",
    help="Stream Memory Studio — local-first AI context migrator & Sandbar Stream MCP manager. Run with no args to launch the Studio UI.",
    no_args_is_help=False,
)
auth_app = typer.Typer(help="Manage legitimate OAuth 2.1 Sandbar connections.")
app.add_typer(auth_app, name="auth")


def _default_data_dir() -> Path:
    """Resolve private local data directory cleanly without polluting unrelated working directories.

    Priority:
    1. Explicit `STREAM_MEMORY_DATA_DIR` environment variable.
    2. Local `./data` if already inside a stream-memory-manager repo checkout (or `./data/stream_memory.db` exists).
    3. XDG-style private user data dir `~/.local/share/stream-memory-manager`.
    """
    env_dir = os.environ.get("STREAM_MEMORY_DATA_DIR", "").strip()
    if env_dir:
        return Path(env_dir).expanduser()
    cwd_data = Path.cwd() / "data"
    if (cwd_data / "stream_memory.db").exists():
        return cwd_data
    pyproject = Path.cwd() / "pyproject.toml"
    if pyproject.exists():
        try:
            if 'name = "stream-memory-manager"' in pyproject.read_text(encoding="utf-8"):
                return cwd_data
        except OSError:
            pass
    return Path.home() / ".local" / "share" / "stream-memory-manager"


@app.callback(invoke_without_command=True)
def _default_launch_studio(
    ctx: typer.Context,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    port: Annotated[int, typer.Option("--port")] = 4319,
    no_browser: Annotated[bool, typer.Option("--no-browser")] = False,
) -> None:
    """Launch Stream Memory Studio automatically when invoked with no subcommand."""
    if ctx.invoked_subcommand is None:
        cmd_ui(data_dir=data_dir, port=port, open_browser=not no_browser)


console = Console(stderr=False)


def _open_db(data_dir: Path, *, read_only: bool = False) -> Database:
    if not read_only:
        ensure_private_dir(data_dir)
    return Database(data_dir / "stream_memory.db", read_only=read_only)


def _rate_limit_key(db: Database, *, server_url: str, profile: str) -> str:
    binding = AccountBindingManager(db).get_latest_for_profile(profile)
    acct_id = (
        binding.get("account_id") if binding and binding.get("server_url") == server_url else None
    )
    return canonical_account_scope(server_url=server_url, account_id=acct_id, profile_name=profile)


def _emit(payload: Any, *, as_json: bool, title: str = "") -> None:
    safe_payload = redact_object(payload)
    if as_json:
        typer.echo(json.dumps(safe_payload, indent=2, sort_keys=True, ensure_ascii=False))
        return
    if title:
        console.print(f"[bold]{rich_escape(title)}[/bold]")
    if isinstance(safe_payload, dict):
        table = Table(show_header=False, box=None)
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        for k, v in safe_payload.items():
            rendered = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
            if len(rendered) > 160:
                rendered = rendered[:157] + "..."
            table.add_row(rich_escape(str(k)), rich_escape(rendered))
        console.print(table)
    else:
        console.print(safe_payload, markup=False)


def _fail(exc: StreamMemoryError, *, as_json: bool) -> None:
    safe_msg = redact_secrets(str(exc))
    err_obj = {
        "error": safe_msg,
        "error_class": exc.error_class.value,
        "exit_code": int(exc.exit_code),
        "details": redact_object(exc.details),
    }
    if as_json:
        typer.echo(json.dumps(err_obj, indent=2, sort_keys=True))
    else:
        console.print(
            f"[bold red]ERROR ({rich_escape(exc.error_class.value)}):[/bold red] {rich_escape(safe_msg)}"
        )
    raise typer.Exit(code=int(exc.exit_code))


@app.command("status")
def cmd_status(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    mode: Annotated[ExecutionMode, typer.Option("--mode")] = ExecutionMode.DRY_RUN,
    profile: Annotated[str, typer.Option("--profile")] = "default",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect compact machine-readable system state and next safe action."""
    try:
        db = _open_db(data_dir)
        try:
            snap = compute_system_status(db=db, mode=mode, profile=profile)
        finally:
            db.close()
        _emit(snap, as_json=as_json, title="Stream Memory Manager Status")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("doctor")
def cmd_doctor(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Verify local DB integrity, file permissions, writer locks, and capability health."""
    try:
        db = _open_db(data_dir)
        try:
            diag = run_doctor(db, data_dir=data_dir, profile=profile)
        finally:
            db.close()
        _emit(diag, as_json=as_json, title="Doctor Diagnostics")
        if not diag["healthy"]:
            raise typer.Exit(code=int(ExitCode.PERMANENT_FAILURE))
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@auth_app.command("connect")
def cmd_auth_connect(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    scope: Annotated[str, typer.Option("--scope")] = "stream",
    open_browser: Annotated[bool, typer.Option("--open-browser/--no-browser")] = True,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    confirm_account: Annotated[bool, typer.Option("--confirm-account")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Connect Sandbar via OAuth 2.1 + PKCE S256 (does NOT authorize any remote writes)."""
    try:
        ensure_private_dir(data_dir)
        storage = SecureTokenStorage(
            profile=profile,
            server_url=server_url,
            fallback_dir=data_dir / "credentials",
            use_keyring=use_keyring,
        )
        res = asyncio.run(
            run_interactive_oauth_connect(
                server_url=server_url,
                storage=storage,
                scope=scope,
                open_browser=open_browser,
                allow_localhost_http=allow_localhost_http,
            )
        )
        db = _open_db(data_dir)
        try:
            bindings = AccountBindingManager(db)
            binding = bindings.upsert_binding(
                profile_name=profile,
                server_url=server_url,
                issuer=str(res["issuer"]),
                account_id=res.get("inferred_subject"),
                account_id_verified=False,  # Never mark unverified JWT decode as server-verified!
                confirmed_by_user=confirm_account,
                reset_unverified_confirmation=True,
            )
        finally:
            db.close()
        res["account_binding_hash"] = binding["binding_hash"]
        res["writes_authorized"] = False
        res["note"] = (
            "OAuth connection succeeded. No remote writes are authorized until a plan is explicitly approved."
        )
        _emit(res, as_json=as_json, title="OAuth Connection")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@auth_app.command("disconnect")
def cmd_auth_disconnect(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    revocation_url: Annotated[str | None, typer.Option("--revocation-url")] = None,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Revoke OAuth credentials (both refresh & access tokens) and erase local tokens cleanly."""
    try:
        storage = SecureTokenStorage(
            profile=profile,
            server_url=server_url,
            fallback_dir=data_dir / "credentials",
            use_keyring=use_keyring,
        )
        res = asyncio.run(
            revoke_and_disconnect(
                storage=storage,
                server_url=server_url,
                revocation_url=revocation_url,
                allow_localhost_http=allow_localhost_http,
            )
        )
        _emit(res, as_json=as_json, title="OAuth Disconnected")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("capabilities")
def cmd_capabilities(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    live: Annotated[bool, typer.Option("--live/--offline")] = False,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect cached or live read-only Sandbar MCP server capabilities."""
    try:
        db = _open_db(data_dir)
        try:
            store = CapabilityStore(db)
            if live:
                storage = SecureTokenStorage(
                    profile=profile,
                    server_url=server_url,
                    fallback_dir=data_dir / "credentials",
                    use_keyring=use_keyring,
                )
                sched = AccountRateScheduler(
                    db, _rate_limit_key(db, server_url=server_url, profile=profile)
                )
                adapter = SandbarMCPAdapter(
                    server_url=server_url,
                    scheduler=sched,
                    storage=storage,
                    allow_localhost_http=allow_localhost_http,
                )
                caps = asyncio.run(adapter.discover_capabilities())
                store.save_snapshot(caps)
            else:
                caps = store.get_latest(server_url) or default_offline_documented_capabilities(
                    server_url
                )
        finally:
            db.close()
        _emit(caps.model_dump(), as_json=as_json, title="Sandbar MCP Capabilities")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("ingest")
def cmd_ingest(
    source: Annotated[
        Path, typer.Argument(help="Markdown, plain-text, or JSON source file to ingest")
    ],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    source_format: Annotated[str, typer.Option("--format")] = "auto",
    approve_clean: Annotated[bool, typer.Option("--approve-clean")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Ingest a source document into the local canonical knowledge registry (local-only)."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            res = ingest_file(
                reg, source, source_format=source_format, default_approve=approve_clean
            )
            rec_res = reconcile_registry(reg)
            local_rules = data_dir / "local_privacy_rules.json"
            priv_res = evaluate_registry_privacy(
                reg, local_rules_path=local_rules if local_rules.exists() else None
            )
            out = {
                "ingestion": res,
                "reconciliation": {
                    "superseded_count": len(rec_res["superseded_applied"]),
                    "exact_duplicates": len(rec_res["exact_duplicates"]),
                    "contradictions": len(rec_res["contradictions"]),
                    "active_eligible_count": rec_res["active_eligible_count"],
                },
                "privacy": {
                    "hard_blocked": len(priv_res["hard_blocked"]),
                    "needs_review": len(priv_res["needs_review"]),
                    "approved_clean": len(priv_res["approved_clean"]),
                },
            }
        finally:
            db.close()
        _emit(out, as_json=as_json, title="Source Ingestion Complete")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("records")
def cmd_records(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    category: Annotated[str | None, typer.Option("--category")] = None,
    status: Annotated[str | None, typer.Option("--status")] = None,
    inclusion: Annotated[str | None, typer.Option("--inclusion")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List canonical records in the local registry (titles & metadata only; never dumps sensitive bodies)."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            recs = reg.list_records(category=category, status=status, inclusion_decision=inclusion)
            summary = [
                {
                    "logical_id": r["logical_id"],
                    "rev": r["current_revision"],
                    "category": r["category"],
                    "title": r["title"],
                    "status": r["status"],
                    "privacy": r["privacy_classification"],
                    "inclusion": r["inclusion_decision"],
                    "eligible": r["destination_eligible"],
                    "sync_status": r["sync_status"],
                }
                for r in recs
            ]
        finally:
            db.close()
        _emit(
            {"count": len(summary), "records": summary}, as_json=as_json, title="Canonical Records"
        )
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("inspect")
def cmd_inspect(
    logical_id: Annotated[str, typer.Argument()],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect a single canonical record, its claims, provenance, and relationships."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            rec = reg.get_record(logical_id)
            if rec is None:
                raise StreamMemoryError(
                    f"Record not found: {logical_id}", exit_code=ExitCode.VALIDATION_ERROR
                )
        finally:
            db.close()
        _emit(rec, as_json=as_json, title=f"Record {logical_id}")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("conflicts")
def cmd_conflicts(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    all_issues: Annotated[bool, typer.Option("--all")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List open reconciliation conflicts, duplicates, privacy blocks, and prompt-injection warnings."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            issues = reg.list_issues(status=None if all_issues else "OPEN")
        finally:
            db.close()
        _emit(
            {"count": len(issues), "issues": issues},
            as_json=as_json,
            title="Reconciliation & Privacy Issues",
        )
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("privacy-review")
def cmd_privacy_review(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    approve_id: Annotated[list[str] | None, typer.Option("--approve")] = None,
    exclude_id: Annotated[list[str] | None, typer.Option("--exclude")] = None,
    approve_all_clean: Annotated[bool, typer.Option("--approve-all-clean")] = False,
    ack_sensitive: Annotated[bool, typer.Option("--ack-sensitive")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Audit privacy classifications and apply explicit user inclusion/exclusion decisions."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            local_rules = data_dir / "local_privacy_rules.json"
            rules_arg = local_rules if local_rules.exists() else None
            for lid in approve_id or []:
                rec = reg.get_record(lid)
                if rec is None:
                    raise StreamMemoryError(
                        f"Record not found: {lid}", exit_code=ExitCode.VALIDATION_ERROR
                    )
                pclass = PrivacyClassification(str(rec["privacy_classification"]))
                if pclass in (
                    PrivacyClassification.SENSITIVE_REVIEW_REQUIRED,
                    PrivacyClassification.GENERALIZED_REQUIRED,
                ):
                    if not ack_sensitive:
                        raise StreamMemoryError(
                            f"Record {lid} is marked {pclass.value}; pass `--ack-sensitive` to explicitly confirm approval.",
                            exit_code=ExitCode.APPROVAL_REQUIRED,
                        )
                    reg.set_decision(
                        lid,
                        privacy_classification=PrivacyClassification.PERSONAL_APPROVED,
                        inclusion_decision=InclusionDecision.APPROVED,
                    )
                else:
                    reg.set_decision(lid, inclusion_decision=InclusionDecision.APPROVED)
            for lid in exclude_id or []:
                reg.set_decision(
                    lid, inclusion_decision=InclusionDecision.EXCLUDED, destination_eligible=False
                )
            res = evaluate_registry_privacy(reg, local_rules_path=rules_arg)
            if approve_all_clean:
                approved_now: list[str] = []
                for item in res["needs_review"]:
                    if item["rules"] == ["pending_explicit_inclusion"]:
                        rec_row = reg.get_record(str(item["logical_id"]))
                        if rec_row is None or not rec_row["destination_eligible"]:
                            continue
                        if str(rec_row["status"]) in ("SUPERSEDED", "DRAFT", "ARCHIVED"):
                            continue
                        reg.set_decision(
                            str(item["logical_id"]), inclusion_decision=InclusionDecision.APPROVED
                        )
                        approved_now.append(str(item["logical_id"]))
                res = evaluate_registry_privacy(reg, local_rules_path=rules_arg)
                res["approved_in_this_call"] = approved_now
        finally:
            db.close()
        _emit(res, as_json=as_json, title="Privacy & Inclusion Review")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("compile")
def cmd_compile(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    max_words: Annotated[int, typer.Option("--max-words")] = 900,
    include_index: Annotated[bool, typer.Option("--index/--no-index")] = True,
    include_briefing: Annotated[bool, typer.Option("--briefing/--no-briefing")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Deterministically compile approved canonical records into <=900-word Stream Logs."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            res = compile_memory(
                reg,
                max_words=max_words,
                include_index=include_index,
                include_briefing=include_briefing,
            )
        finally:
            db.close()
        _emit(res, as_json=as_json, title="Memory Compilation Complete")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("plan")
def cmd_plan(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    mode: Annotated[ExecutionMode, typer.Option("--mode")] = ExecutionMode.DRY_RUN,
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    target_folder: Annotated[str, typer.Option("--folder")] = "Memory",
    include_briefing: Annotated[bool, typer.Option("--include-briefing")] = False,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Generate an immutable draft import plan without mutating remote state."""
    try:
        if mode != ExecutionMode.DRY_RUN:
            validate_endpoint_url(
                server_url, allow_localhost_http=allow_localhost_http, expected_mode=mode
            )
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            planner = ImportPlanner(db, reg)
            bindings = AccountBindingManager(db)
            cap_store = CapabilityStore(db)

            if mode == ExecutionMode.DRY_RUN:
                caps = cap_store.get_latest(server_url) or default_offline_documented_capabilities(
                    server_url
                )
                binding = bindings.upsert_binding(
                    profile_name=profile,
                    server_url=server_url,
                    issuer=server_url.rsplit("/mcp", 1)[0],
                    account_id="dry-run-local",
                    account_id_verified=False,
                    target_folder_name=target_folder,
                    confirmed_by_user=True,
                )
                remote_state = ObservedRemoteState(is_offline_assumption=True)
            else:
                storage = SecureTokenStorage(
                    profile=profile,
                    server_url=server_url,
                    fallback_dir=data_dir / "credentials",
                    use_keyring=use_keyring,
                )
                sched = AccountRateScheduler(
                    db, _rate_limit_key(db, server_url=server_url, profile=profile)
                )
                adapter = SandbarMCPAdapter(
                    server_url=server_url,
                    scheduler=sched,
                    storage=storage,
                    allow_localhost_http=allow_localhost_http,
                    expected_mode=mode,
                )
                caps = asyncio.run(adapter.discover_capabilities())
                cap_store.save_snapshot(caps)
                remote_state = asyncio.run(
                    observe_remote_state(adapter, target_folder_name=target_folder)
                )
                binding = bindings.upsert_binding(
                    profile_name=profile,
                    server_url=server_url,
                    issuer=remote_state.observed_issuer or server_url.rsplit("/mcp", 1)[0],
                    account_id=remote_state.observed_account_id,
                    account_id_verified=remote_state.account_id_verified,
                    target_folder_name=target_folder,
                    target_folder_id=(
                        remote_state.memory_folder_matches[0].folder_id
                        if len(remote_state.memory_folder_matches) == 1
                        else None
                    ),
                    confirmed_by_user=remote_state.account_id_verified,
                )

            plan = planner.build_plan(
                mode=mode,
                account_binding_hash=binding["binding_hash"],
                capabilities=caps,
                remote_state=remote_state,
                target_folder_name=target_folder,
                include_briefing=include_briefing,
                budget=RequestBudget(),
            )
        finally:
            db.close()

        preview_out = {
            "plan_id": plan["plan_id"],
            "mode": plan["mode"],
            "status": plan["status"],
            "target_folder": plan["target_folder_name"],
            "capability_fingerprint": plan["capability_fingerprint"][:16],
            "summary": plan["summary"],
            "assumptions": plan["assumptions"],
            "next_safe_action": f"stream-memory preview --plan-id {plan['plan_id']}",
        }
        _emit(preview_out, as_json=as_json, title="Draft Import Plan Created (No Remote Writes)")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("diff")
def cmd_diff(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show differences between compiled local artifacts and verified remote sync state."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            arts = load_compiled_artifacts(reg)
            to_create: list[str] = []
            already_verified: list[str] = []
            changed_verified: list[str] = []
            for art in arts:
                if art.artifact_kind != "log":
                    continue
                row = db.conn.execute(
                    """
                    SELECT normalized_payload_hash, remote_id FROM operations
                    WHERE logical_id = ? AND state = 'VERIFIED'
                    ORDER BY updated_at DESC LIMIT 1;
                    """,
                    (art.artifact_key,),
                ).fetchone()
                if not row:
                    to_create.append(art.title)
                elif str(row["normalized_payload_hash"]) == art.normalized_payload_hash:
                    already_verified.append(art.title)
                else:
                    changed_verified.append(art.title)
            out = {
                "compiled_logs": len([a for a in arts if a.artifact_kind == "log"]),
                "new_to_create": len(to_create),
                "unchanged_verified": len(already_verified),
                "changed_after_verify": len(changed_verified),
                "titles_to_create": to_create,
                "titles_changed": changed_verified,
            }
        finally:
            db.close()
        _emit(out, as_json=as_json, title="Local vs Verified Remote Diff")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("preview")
def cmd_preview(
    plan_id: Annotated[str, typer.Option("--plan-id")],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    show_bodies: Annotated[bool, typer.Option("--show-bodies")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect every planned operation, word count, conflict, and non-reversibility warning (non-mutating)."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            planner = ImportPlanner(db, reg)
            plan = planner.get_plan(plan_id)
        finally:
            db.close()
        ops_view = []
        for op in plan["operations"]:
            p = op["payload"]
            entry: dict[str, Any] = {
                "seq": op["sequence_num"],
                "batch": op["batch_num"],
                "op_id": op["op_id"],
                "op_type": op["op_type"],
                "state": op["state"],
                "logical_id": op["logical_id"],
                "title": p.get("title") or p.get("name") or op["op_type"],
                "payload_hash": str(op["payload_hash"])[:16],
            }
            if show_bodies and "body" in p:
                entry["body"] = p["body"]
            ops_view.append(entry)
        out = {
            "plan_id": plan["plan_id"],
            "mode": plan["mode"],
            "status": plan["status"],
            "target_folder": plan["target_folder_name"],
            "account_binding_hash": plan["account_binding_hash"],
            "capability_fingerprint": plan["capability_fingerprint"],
            "summary": plan["summary"],
            "assumptions": plan["assumptions"],
            "operations": ops_view,
        }
        _emit(out, as_json=as_json, title=f"Plan Preview: {plan_id}")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("approve")
def cmd_approve(
    plan_id: Annotated[str, typer.Option("--plan-id")],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    actor: Annotated[str, typer.Option("--actor")] = "user",
    note: Annotated[str, typer.Option("--note")] = "",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Explicitly approve an exact immutable DRAFT plan_id for bounded execution."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            planner = ImportPlanner(db, reg)
            plan = planner.approve_plan(
                plan_id, actor=actor, note=note, lock_dir=data_dir / "locks"
            )
        finally:
            db.close()
        _emit(
            {
                "plan_id": plan["plan_id"],
                "status": plan["status"],
                "approved_at": plan["approved_at"],
                "approval_actor": plan["approval_actor"],
                "mutating_operations": plan["summary"]["mutating_operations"],
                "next_safe_action": f"stream-memory apply --plan-id {plan['plan_id']} --mode {plan['mode']}",
            },
            as_json=as_json,
            title=f"Plan Approved: {plan_id}",
        )
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("apply")
def cmd_apply(
    plan_id: Annotated[str, typer.Option("--plan-id")],
    mode: Annotated[ExecutionMode, typer.Option("--mode")] = ExecutionMode.DRY_RUN,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Execute an explicitly approved plan_id with strict mode-to-endpoint isolation."""
    try:
        if mode == ExecutionMode.DRY_RUN:
            raise StreamMemoryError(
                "Dry-run mode is strictly non-mutating. Pass `--mode live` (or `--mode mock --allow-localhost-http --server-url http://127.0.0.1:<port>/mcp`) to execute an approved plan.",
                exit_code=ExitCode.APPROVAL_REQUIRED,
            )
        validate_endpoint_url(
            server_url, allow_localhost_http=allow_localhost_http, expected_mode=mode
        )
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            storage = SecureTokenStorage(
                profile=profile,
                server_url=server_url,
                fallback_dir=data_dir / "credentials",
                use_keyring=use_keyring,
            )
            sched = AccountRateScheduler(
                db, _rate_limit_key(db, server_url=server_url, profile=profile)
            )
            adapter = SandbarMCPAdapter(
                server_url=server_url,
                scheduler=sched,
                storage=storage,
                allow_localhost_http=allow_localhost_http,
                expected_mode=mode,
            )
            engine = ExecutionEngine(
                db=db, registry=reg, adapter=adapter, lock_dir=data_dir / "locks"
            )
            report = asyncio.run(
                engine.execute_plan(plan_id, expected_mode=mode, install_signal_handlers=True)
            )
        finally:
            db.close()
        _emit(report.to_dict(), as_json=as_json, title=f"Execution Report: {plan_id}")
        raise typer.Exit(code=int(report.exit_code))
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("pause")
def cmd_pause(
    plan_id: Annotated[str, typer.Option("--plan-id")],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    reason: Annotated[str, typer.Option("--reason")] = "user_paused",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Cancel all not-yet-dispatched operations in a plan atomically under writer lock."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            planner = ImportPlanner(db, reg)
            res = planner.cancel_plan(plan_id, reason=reason, lock_dir=data_dir / "locks")
        finally:
            db.close()
        _emit(res, as_json=as_json, title=f"Plan Paused/Cancelled: {plan_id}")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("resume")
def cmd_resume(
    plan_id: Annotated[str, typer.Option("--plan-id")],
    mode: Annotated[ExecutionMode, typer.Option("--mode")] = ExecutionMode.DRY_RUN,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Safely resume an interrupted approved plan (requires explicit `--mode mock|live`)."""
    cmd_apply(
        plan_id=plan_id,
        mode=mode,
        data_dir=data_dir,
        profile=profile,
        server_url=server_url,
        allow_localhost_http=allow_localhost_http,
        use_keyring=use_keyring,
        as_json=as_json,
    )


@app.command("reconcile")
def cmd_reconcile(
    plan_id: Annotated[str, typer.Option("--plan-id")],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Read-only reconciliation of UNCERTAIN_REMOTE_OUTCOME or AWAITING_VERIFICATION operations."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            storage = SecureTokenStorage(
                profile=profile,
                server_url=server_url,
                fallback_dir=data_dir / "credentials",
                use_keyring=use_keyring,
            )
            sched = AccountRateScheduler(
                db, _rate_limit_key(db, server_url=server_url, profile=profile)
            )
            adapter = SandbarMCPAdapter(
                server_url=server_url,
                scheduler=sched,
                storage=storage,
                allow_localhost_http=allow_localhost_http,
            )
            engine = ExecutionEngine(
                db=db, registry=reg, adapter=adapter, lock_dir=data_dir / "locks"
            )
            report = asyncio.run(engine.reconcile_plan(plan_id))
        finally:
            db.close()
        _emit(report.to_dict(), as_json=as_json, title=f"Reconciliation Report: {plan_id}")
        raise typer.Exit(code=int(report.exit_code))
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("verify")
def cmd_verify(
    plan_id: Annotated[str, typer.Option("--plan-id")],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Verify pending/awaiting-verification remote postconditions read-only."""
    cmd_reconcile(
        plan_id=plan_id,
        data_dir=data_dir,
        profile=profile,
        server_url=server_url,
        allow_localhost_http=allow_localhost_http,
        use_keyring=use_keyring,
        as_json=as_json,
    )


@app.command("export")
def cmd_export(
    output_dir: Annotated[Path, typer.Option("--output-dir")],
    scope: Annotated[str, typer.Option("--scope")] = "stream-ready",
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Export open-format Markdown, JSON, manifest, and provenance bundles."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            res = export_bundle(reg, output_dir, scope=scope)
        finally:
            db.close()
        _emit(res, as_json=as_json, title=f"Export Complete ({scope})")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("backup")
def cmd_backup(
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("data/backups"),
    label: Annotated[str, typer.Option("--label")] = "manual",
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create a WAL-consistent SQLite Online Backup snapshot with SHA-256 metadata."""
    try:
        db = _open_db(data_dir)
        try:
            res = db.backup_to(output_dir, label=label)
        finally:
            db.close()
        _emit(res, as_json=as_json, title="SQLite Online Backup Created")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("restore")
def cmd_restore(
    backup_file: Annotated[Path, typer.Argument()],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    expected_sha256: Annotated[str | None, typer.Option("--expected-sha256")] = None,
    allow_unverified_checksum: Annotated[bool, typer.Option("--allow-unverified-checksum")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Verify checksum, schema, and SQLite integrity before restoring a database snapshot."""
    try:
        res = restore_backup(
            backup_file,
            data_dir / "stream_memory.db",
            expected_sha256=expected_sha256,
            allow_unverified_checksum=allow_unverified_checksum,
        )
        _emit(res, as_json=as_json, title="SQLite Backup Restored")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("evaluate")
def cmd_evaluate(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    queries_file: Annotated[Path | None, typer.Option("--queries-file")] = None,
    native_kit: Annotated[bool, typer.Option("--native-kit")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run local BM25 retrieval evaluation over compiled Logs or print the native Stream evaluation kit."""
    try:
        if native_kit:
            _emit(
                generate_native_evaluation_protocol(),
                as_json=as_json,
                title="Native Stream Manual Evaluation Protocol",
            )
            return
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            res = run_local_retrieval_evaluation(reg, queries_file=queries_file)
        finally:
            db.close()
        _emit(res, as_json=as_json, title="Local Retrieval Evaluation (BM25 Simulation)")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("detect")
def cmd_detect(
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Auto-detect installed local coding agents and list supported web AI services."""
    try:
        res = detect_local_sources()
        _emit(
            res, as_json=as_json, title="Detected Local Coding Agents & Supported Web AI Services"
        )
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("harvest")
def cmd_harvest(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    sources: Annotated[
        str | None,
        typer.Option(
            "--sources", help="Comma-separated local source IDs (omit to harvest all detected)"
        ),
    ] = None,
    max_items: Annotated[int, typer.Option("--max-items")] = 40,
    ingest_after: Annotated[
        bool,
        typer.Option(
            "--ingest/--no-ingest",
            help="Automatically ingest harvested markdown files into the local SQLite registry",
        ),
    ] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Harvest read-only, secret-redacted digests from local coding agents and optionally ingest them."""
    try:
        selected = [s.strip() for s in sources.split(",") if s.strip()] if sources else None
        res = harvest_local_sources(
            data_dir / "harvested",
            sources=selected,
            max_items_per_source=max_items,
        )
        if ingest_after and res.get("written"):
            ingested_total = 0
            ingested_files: list[str] = []
            db = _open_db(data_dir)
            try:
                reg = KnowledgeRegistry(db)
                for item in res["written"]:
                    p = Path(str(item["output_path"]))
                    if p.exists():
                        ires = ingest_file(reg, p)
                        ingested_total += int(ires.get("records_parsed", 0))
                        ingested_files.append(str(p))
            finally:
                db.close()
            res["ingested_records"] = ingested_total
            res["ingested_files"] = ingested_files
        _emit(res, as_json=as_json, title="Local Coding-Agent Harvest Complete")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("harvest-export")
def cmd_harvest_export(
    export_file: Annotated[Path, typer.Argument(help="Official JSON or ZIP chat export file")],
    service: Annotated[str, typer.Option("--service")] = "auto",
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    max_conversations: Annotated[int, typer.Option("--max-conversations")] = 80,
    ingest_after: Annotated[
        bool,
        typer.Option(
            "--ingest/--no-ingest",
            help="Automatically ingest the digested export into the local SQLite registry",
        ),
    ] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Parse an official ChatGPT, Claude, Gemini, DeepSeek, or T3 JSON/ZIP export and ingest into SQLite."""
    try:
        out = data_dir / "harvested" / f"export_{export_file.stem}.md"
        res = parse_web_export_to_markdown(
            export_file, out, service=service, max_conversations=max_conversations
        )
        if ingest_after and out.exists():
            db = _open_db(data_dir)
            try:
                reg = KnowledgeRegistry(db)
                ires = ingest_file(reg, out)
                res["ingested_records"] = int(ires.get("records_parsed", 0))
            finally:
                db.close()
        _emit(res, as_json=as_json, title="Web Export Digested")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("web-prompts")
def cmd_web_prompts(
    services: Annotated[
        str,
        typer.Option(
            "--services",
            help="Comma-separated web AI services the user actually uses (e.g. chatgpt,claude,gemini,t3_chat,grok,deepseek,duck_ai,perplexity)",
        ),
    ],
    mode: Annotated[
        str,
        typer.Option(
            "--mode", help="Extraction mode: 'full' (initial) or 'delta' (only missing updates)"
        ),
    ] = "full",
    covered_from_db: Annotated[
        bool,
        typer.Option(
            "--covered-from-db",
            help="Auto-fill already-covered section titles and next section number from local SQLite DB (saves agent tokens)",
        ),
    ] = False,
    start_section: Annotated[int | None, typer.Option("--start-section")] = None,
    extra_exclusions: Annotated[str | None, typer.Option("--extra-exclusions")] = None,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    raw: Annotated[
        bool,
        typer.Option(
            "--raw",
            help="Output ONLY the ready-to-paste standardized prompt text (for single-service zero-token copy/paste)",
        ),
    ] = False,
    save_dir: Annotated[
        Path | None,
        typer.Option(
            "--save-dir", help="Optionally write prompt_<service>.txt file(s) with 0600 permissions"
        ),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Emit premade, max-thinking, standardized web-chat extraction prompts with minimal slot personalization."""
    try:
        selected = [s.strip() for s in services.split(",") if s.strip()]
        covered_topics: list[str] = []
        resolved_start = start_section if start_section is not None else 0
        if covered_from_db:
            db = _open_db(data_dir)
            try:
                reg = KnowledgeRegistry(db)
                recs = reg.list_records()
                covered_topics = [str(r["title"]) for r in recs if r.get("title")]
                if start_section is None:
                    resolved_start = len(recs)
            finally:
                db.close()
        res = build_web_extraction_kit(
            selected,
            mode=mode,
            covered_topics=covered_topics,
            start_section=resolved_start,
            extra_exclusions=extra_exclusions,
        )
        if save_dir is not None:
            ensure_private_dir(save_dir)
            saved_paths: list[str] = []
            for plan in res["service_plans"]:
                if plan["prompts"]:
                    pfile = save_dir / f"prompt_{plan['service_id']}_{mode}.txt"
                    from stream_memory_manager.security import atomic_write_private_text

                    atomic_write_private_text(pfile, plan["prompts"][0]["prompt"] + "\n")
                    saved_paths.append(str(pfile))
            res["saved_prompt_files"] = saved_paths
        if raw:
            plans = res["service_plans"]
            if len(plans) != 1 or not plans[0]["prompts"]:
                raise StreamMemoryError(
                    "--raw requires exactly one service with an active extraction prompt.",
                    error_class=ErrorClass.VALIDATION_PERMANENT,
                    exit_code=ExitCode.VALIDATION_ERROR,
                )
            typer.echo(plans[0]["prompts"][0]["prompt"])
            return
        _emit(res, as_json=as_json, title="Premade Max-Thinking Web AI Extraction Prompt Kit")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("consolidate")
def cmd_consolidate(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    similarity: Annotated[float, typer.Option("--similarity")] = 0.24,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Analyze active records to surface overlapping merge candidates, sparse fragments, and meta-boilerplate."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            res = analyze_corpus(reg, similarity_threshold=similarity)
        finally:
            db.close()
        _emit(res, as_json=as_json, title="Corpus Consolidation & Hygiene Analysis")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("merge")
def cmd_merge(
    record_ids: Annotated[
        list[str], typer.Argument(help="Two or more logical_ids to consolidate into one dossier")
    ],
    title: Annotated[str, typer.Option("--title", help="Title for the unified Topic Dossier")],
    category: Annotated[str | None, typer.Option("--category")] = None,
    body_file: Annotated[
        Path | None,
        typer.Option("--body-file", help="Optional path to curated merged Markdown body"),
    ] = None,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Merge 2+ overlapping records into ONE dense canonical Topic Dossier and supersede absorbed fragments."""
    try:
        merged_body = body_file.read_text(encoding="utf-8") if body_file else None
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            res = merge_records(
                reg,
                record_ids,
                target_title=title,
                target_category=category,
                merged_body=merged_body,
                approve=True,
            )
            evaluate_registry_privacy(reg)
        finally:
            db.close()
        _emit(res, as_json=as_json, title="Topic Dossier Merged")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("agent-pack")
def cmd_agent_pack(
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Optional path to write the agent consolidation JSON pack"
        ),
    ] = None,
    similarity: Annotated[float, typer.Option("--similarity")] = 0.24,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Export an agent-native overlap-cluster & full-record pack for the driving coding agent to synthesize."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            pack = build_agent_consolidation_pack(reg, similarity_threshold=similarity)
        finally:
            db.close()
        if output is not None:
            out_path = output.expanduser().resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(pack, indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
            _emit(
                {
                    "output_path": str(out_path),
                    "stats": pack["stats"],
                    "overlap_clusters": len(pack["overlap_clusters"]),
                },
                as_json=as_json,
                title="Agent Consolidation Pack Exported",
            )
            return
        _emit(pack, as_json=True, title="Agent Consolidation Pack")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("apply-dossiers")
def cmd_apply_dossiers(
    dossiers_file: Annotated[
        Path,
        typer.Argument(
            help="JSON file produced by the driving agent with consolidated `dossiers` and optional `retire_ids`"
        ),
    ],
    compile_after: Annotated[
        bool,
        typer.Option(
            "--compile/--no-compile",
            help="Run privacy check and compile Stream Notes + Briefing immediately",
        ),
    ] = True,
    include_index: Annotated[
        bool,
        typer.Option(
            "--include-index/--no-index",
            help="Include separate Table of Contents Log when compiling",
        ),
    ] = False,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Atomically apply a driving coding agent's synthesized dense Topic Dossiers and compile."""
    try:
        raw_path = dossiers_file.expanduser().resolve()
        if not raw_path.exists():
            raise StreamMemoryError(
                f"Dossiers file not found: {raw_path}",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        try:
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise StreamMemoryError(
                f"Invalid JSON in {raw_path}: {exc}",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            ) from exc
        if not isinstance(payload, dict):
            raise StreamMemoryError(
                "Dossiers JSON root must be an object with a `dossiers` list.",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )

        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            res = apply_agent_dossiers(reg, payload, approve=True)
            priv = evaluate_registry_privacy(reg)
            res["privacy_summary"] = {
                "hard_blocked": len(priv["hard_blocked"]),
                "needs_review": len(priv["needs_review"]),
                "approved_clean": len(priv["approved_clean"]),
                "hard_blocked_items": priv["hard_blocked"],
                "needs_review_items": priv["needs_review"],
            }
            if compile_after:
                comp = compile_memory(reg, include_index=include_index)
                res["compile"] = comp
                if comp.get("skipped_unapproved_eligible", 0) > 0:
                    res["warning"] = (
                        f"{comp['skipped_unapproved_eligible']} dossier(s) were paused for privacy review "
                        "and omitted from compilation; inspect `privacy_summary.needs_review_items`."
                    )
        finally:
            db.close()
        _emit(res, as_json=as_json, title="Agent-Synthesized Topic Dossiers Applied")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("inspect-live")
def cmd_inspect_live(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    folder: Annotated[str, typer.Option("--folder")] = "Memory",
    archive_folder: Annotated[str, typer.Option("--archive-folder")] = DEFAULT_ARCHIVE_FOLDER_NAME,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inspect live Sandbar Memory & Memory Archive folders read-only and diff against compiled local Dossiers."""
    try:
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            compiled_logs = [a for a in load_compiled_artifacts(reg) if a.artifact_kind == "log"]
            storage = SecureTokenStorage(
                profile=profile,
                server_url=server_url,
                fallback_dir=data_dir / "credentials",
                use_keyring=use_keyring,
            )
            sched = AccountRateScheduler(
                db, _rate_limit_key(db, server_url=server_url, profile=profile)
            )
            adapter = SandbarMCPAdapter(
                server_url=server_url,
                scheduler=sched,
                storage=storage,
                allow_localhost_http=allow_localhost_http,
                expected_mode=ExecutionMode.MOCK if allow_localhost_http else ExecutionMode.LIVE,
                capabilities=CapabilityStore(db).get_latest(server_url),
            )
            managed_ids = db.list_managed_remote_ids()
            res = asyncio.run(
                inspect_live_memory_state(
                    adapter,
                    compiled_logs,
                    target_folder_name=folder,
                    archive_folder_name=archive_folder,
                    managed_artifact_ids=managed_ids,
                )
            )
        finally:
            db.close()
        _emit(res, as_json=as_json, title="Live Sandbar Stream Memory Diff")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("reset-memory")
def cmd_reset_memory(
    confirm_reset: Annotated[
        bool,
        typer.Option(
            "--confirm-reset",
            help="Required explicit confirmation to move live Memory notes into Memory Archive via official MCP",
        ),
    ] = False,
    stale_only: Annotated[
        bool,
        typer.Option(
            "--stale-only",
            help="Move stale/superseded (and optionally changed) managed notes out of Memory while keeping in-sync and personal notes untouched",
        ),
    ] = False,
    include_changed: Annotated[
        bool,
        typer.Option(
            "--include-changed/--no-include-changed",
            help="With --stale-only, also archive managed notes whose title matches a locally modified dossier so re-push replaces cleanly",
        ),
    ] = True,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    folder: Annotated[str, typer.Option("--folder")] = "Memory",
    archive_folder: Annotated[str, typer.Option("--archive-folder")] = DEFAULT_ARCHIVE_FOLDER_NAME,
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Safely quarantine stale or ALL live Memory notes into `Memory Archive` via official MCP `set_note_folder`."""
    try:
        if not confirm_reset:
            raise StreamMemoryError(
                "Refusing to quarantine live Memory notes without explicit `--confirm-reset`.",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.APPROVAL_REQUIRED,
            )
        db = _open_db(data_dir)
        try:
            reg = KnowledgeRegistry(db)
            storage = SecureTokenStorage(
                profile=profile,
                server_url=server_url,
                fallback_dir=data_dir / "credentials",
                use_keyring=use_keyring,
            )
            sched = AccountRateScheduler(
                db, _rate_limit_key(db, server_url=server_url, profile=profile)
            )
            adapter = SandbarMCPAdapter(
                server_url=server_url,
                scheduler=sched,
                storage=storage,
                allow_localhost_http=allow_localhost_http,
                expected_mode=ExecutionMode.MOCK if allow_localhost_http else ExecutionMode.LIVE,
                capabilities=CapabilityStore(db).get_latest(server_url),
            )
            target_ids: list[str] | None = None
            if stale_only:
                compiled_logs = [
                    a for a in load_compiled_artifacts(reg) if a.artifact_kind == "log"
                ]
                managed_ids = db.list_managed_remote_ids()
                live = asyncio.run(
                    inspect_live_memory_state(
                        adapter,
                        compiled_logs,
                        target_folder_name=folder,
                        archive_folder_name=archive_folder,
                        managed_artifact_ids=managed_ids,
                    )
                )
                target_ids = [str(x["remote_id"]) for x in live["stale_in_stream"]]
                if include_changed:
                    target_ids.extend(
                        str(x["remote_id"]) for x in live["changed_local"] if x.get("remote_id")
                    )
                target_ids = list(dict.fromkeys(target_ids))
            res = asyncio.run(
                quarantine_logs_to_archive(
                    adapter,
                    target_folder_name=folder,
                    archive_folder_name=archive_folder,
                    artifact_ids=target_ids,
                )
            )
        finally:
            db.close()
        _emit(res, as_json=as_json, title="Live Memory Quarantine Complete")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("search-live")
def cmd_search_live(
    query: Annotated[
        str, typer.Argument(help="Natural-language query to test against live Stream Memory")
    ],
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    profile: Annotated[str, typer.Option("--profile")] = "default",
    server_url: Annotated[str, typer.Option("--server-url")] = SANDBAR_OFFICIAL_MCP_URL,
    folder: Annotated[str, typer.Option("--folder")] = "Memory",
    allow_localhost_http: Annotated[bool, typer.Option("--allow-localhost-http")] = False,
    use_keyring: Annotated[bool, typer.Option("--use-keyring/--file-token-store")] = True,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Test live conversational retrieval against your Sandbar Stream Memory folder."""
    try:
        db = _open_db(data_dir)
        try:
            storage = SecureTokenStorage(
                profile=profile,
                server_url=server_url,
                fallback_dir=data_dir / "credentials",
                use_keyring=use_keyring,
            )
            sched = AccountRateScheduler(
                db, _rate_limit_key(db, server_url=server_url, profile=profile)
            )
            adapter = SandbarMCPAdapter(
                server_url=server_url,
                scheduler=sched,
                storage=storage,
                allow_localhost_http=allow_localhost_http,
                expected_mode=ExecutionMode.MOCK if allow_localhost_http else ExecutionMode.LIVE,
                capabilities=CapabilityStore(db).get_latest(server_url),
            )

            async def _run() -> dict[str, Any]:
                if adapter.capabilities is None:
                    caps = await adapter.discover_capabilities()
                    CapabilityStore(db).save_snapshot(caps)
                folders = await adapter.list_folders()
                mem = next((f for f in folders if f.name == folder), None)
                hits = await adapter.search_logs(query, folder_id=mem.folder_id if mem else None)
                return {
                    "query": query,
                    "hit_count": len(hits),
                    "hits": [
                        {
                            "rank": i,
                            "artifact_id": h.artifact_id,
                            "title": h.title,
                            "preview": h.body[:200].replace("\n", " "),
                        }
                        for i, h in enumerate(hits, start=1)
                    ],
                }

            res = asyncio.run(_run())
        finally:
            db.close()
        _emit(res, as_json=as_json, title=f"Live Stream Search: {query}")
    except StreamMemoryError as exc:
        _fail(exc, as_json=as_json)


@app.command("ui")
def cmd_ui(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = _default_data_dir(),
    port: Annotated[int, typer.Option("--port")] = 4319,
    open_browser: Annotated[bool, typer.Option("--open/--no-browser")] = False,
) -> None:
    """Launch Stream Memory Studio (unified 4-tab local web app) strictly on http://127.0.0.1:<port>/view."""
    from stream_memory_manager.web_ui import run_staging_ui

    ensure_private_dir(data_dir)
    _open_db(data_dir).close()
    typer.echo(f"Starting Stream Memory Studio at http://127.0.0.1:{port}/view")
    typer.echo("Bound strictly to 127.0.0.1 (CSRF-protected). Press Ctrl+C to stop.")
    run_staging_ui(data_dir, port=port, open_browser=open_browser)


def main() -> None:
    try:
        app()
    except StreamMemoryError as exc:
        typer.echo(f"ERROR ({exc.error_class.value}): {redact_secrets(str(exc))}", err=True)
        sys.exit(int(exc.exit_code))
