"""End-to-end CLI contract tests: --json snapshots, exit codes, dry-run guards, export, backup/restore."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from stream_memory_manager.cli import app
from stream_memory_manager.models import ExitCode

runner = CliRunner()


def test_cli_full_local_workflow_json_contracts_and_exit_codes(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    src_file = tmp_path / "synthetic_context.md"
    src_file.write_text(
        "# Core Personal Context\n\n"
        "Alex Mercer studies Public Policy and builds reliable local-first tools.\n\n"
        "# Hardware Notes\n\n"
        "Orbital65 keyboard tested physically over USB HID.\n",
        encoding="utf-8",
    )

    # 1. status on empty DB
    res = runner.invoke(app, ["status", "--data-dir", str(data_dir), "--json"])
    assert res.exit_code == ExitCode.SUCCESS
    st = json.loads(res.stdout)
    assert st["blocked_reason"] == "NO_RECORDS_INGESTED"
    assert st["remote_writes_allowed"] is False

    # 2. ingest
    res = runner.invoke(app, ["ingest", str(src_file), "--data-dir", str(data_dir), "--json"])
    assert res.exit_code == ExitCode.SUCCESS
    ing = json.loads(res.stdout)
    assert ing["ingestion"]["created"] == 2

    # 3. privacy-review --approve-all-clean
    res = runner.invoke(
        app, ["privacy-review", "--data-dir", str(data_dir), "--approve-all-clean", "--json"]
    )
    assert res.exit_code == ExitCode.SUCCESS
    priv = json.loads(res.stdout)
    assert len(priv["approved_clean"]) == 2

    # 4. compile
    res = runner.invoke(app, ["compile", "--data-dir", str(data_dir), "--json"])
    assert res.exit_code == ExitCode.SUCCESS
    comp = json.loads(res.stdout)
    assert comp["compiled_log_count"] == 3  # 2 logs + 1 CORE Knowledge Index

    # 5. plan (dry-run)
    res = runner.invoke(app, ["plan", "--data-dir", str(data_dir), "--mode", "dry-run", "--json"])
    assert res.exit_code == ExitCode.SUCCESS
    plan = json.loads(res.stdout)
    plan_id = plan["plan_id"]
    assert plan["status"] == "DRAFT"

    # 6. preview
    res = runner.invoke(
        app, ["preview", "--plan-id", plan_id, "--data-dir", str(data_dir), "--json"]
    )
    assert res.exit_code == ExitCode.SUCCESS
    prev = json.loads(res.stdout)
    assert len(prev["operations"]) >= 4

    # 7. apply in dry-run mode MUST fail closed with APPROVAL_REQUIRED!
    res = runner.invoke(
        app,
        ["apply", "--plan-id", plan_id, "--mode", "dry-run", "--data-dir", str(data_dir), "--json"],
    )
    assert res.exit_code == int(ExitCode.APPROVAL_REQUIRED)

    # 8. approve + pause
    res = runner.invoke(
        app, ["approve", "--plan-id", plan_id, "--data-dir", str(data_dir), "--json"]
    )
    assert res.exit_code == ExitCode.SUCCESS
    assert json.loads(res.stdout)["status"] == "APPROVED"

    res = runner.invoke(app, ["pause", "--plan-id", plan_id, "--data-dir", str(data_dir), "--json"])
    assert res.exit_code == ExitCode.SUCCESS
    assert json.loads(res.stdout)["cancelled_before_write"] >= 4

    # 9. doctor + export + backup + restore + evaluate --native-kit
    res = runner.invoke(app, ["doctor", "--data-dir", str(data_dir), "--json"])
    assert res.exit_code == ExitCode.SUCCESS
    assert json.loads(res.stdout)["healthy"] is True

    exp_dir = tmp_path / "export_out"
    res = runner.invoke(
        app,
        [
            "export",
            "--output-dir",
            str(exp_dir),
            "--scope",
            "stream-ready",
            "--data-dir",
            str(data_dir),
            "--json",
        ],
    )
    assert res.exit_code == ExitCode.SUCCESS
    assert (exp_dir / "manifest.json").exists()
    assert (exp_dir / "consolidated_stream_ready.md").exists()

    bak_dir = tmp_path / "backups"
    res = runner.invoke(
        app, ["backup", "--output-dir", str(bak_dir), "--data-dir", str(data_dir), "--json"]
    )
    assert res.exit_code == ExitCode.SUCCESS
    bak_path = json.loads(res.stdout)["backup_path"]

    restore_dir = tmp_path / "restored_data"
    res = runner.invoke(app, ["restore", bak_path, "--data-dir", str(restore_dir), "--json"])
    assert res.exit_code == ExitCode.SUCCESS

    res = runner.invoke(app, ["evaluate", "--native-kit", "--json"])
    assert res.exit_code == ExitCode.SUCCESS
    assert json.loads(res.stdout)["execution_mode"] == "MANUAL_NATIVE_STREAM_CONVERSATION"
