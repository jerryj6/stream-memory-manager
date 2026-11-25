"""Tests for V2 consolidation, hygiene triage, clean voice prose, deep repo harvest, live quarantine, and Studio API."""

from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

from stream_memory_manager.compiler import compile_memory, load_compiled_artifacts
from stream_memory_manager.consolidator import (
    analyze_corpus,
    merge_records,
    strip_robotic_tag_prefixes,
)
from stream_memory_manager.db import Database
from stream_memory_manager.harvesters import detect_local_sources, harvest_local_sources
from stream_memory_manager.mcp_adapter import (
    SandbarMCPAdapter,
    inspect_live_memory_state,
    quarantine_logs_to_archive,
)
from stream_memory_manager.mock_server import RunningMockServer
from stream_memory_manager.models import (
    EvidenceClass,
    ExecutionMode,
    InclusionDecision,
    MemoryRecordInput,
    RecordStatus,
)
from stream_memory_manager.rate_limit import AccountRateScheduler
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.web_ui import create_staging_ui_app


def test_consolidator_detects_overlap_hygiene_and_merges_cleanly(tmp_db: Database) -> None:
    reg = KnowledgeRegistry(tmp_db)
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="rec_kbd_1",
            title="Mechanical Keyboard Reverse Engineering",
            category="HARDWARE",
            body=(
                "- [Confirmed] (2026-10) Built a custom Swift HID driver for the Orbital65 wireless keyboard.\n"
                "- [Confirmed] (2026-10) Tested USB packet framing over report page 0xFF60."
            ),
            evidence_class=EvidenceClass.USER_CONFIRMED,
            last_confirmed_date="2026-10-15",
            source_refs=["src_a#1"],
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="rec_kbd_2",
            title="Orbital65 Keyboard Wireless Protocol Delta",
            category="HARDWARE",
            body=(
                "- [Confirmed] (2026-11) Built a custom Swift HID driver for the Orbital65 wireless keyboard.\n"
                "- [OpenLoop] (2026-11) Still validating audio-reactive LED latency over wired USB."
            ),
            evidence_class=EvidenceClass.ARTIFACT_INSPECTED,
            last_confirmed_date="2026-11-20",
            source_refs=["src_b#2"],
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="rec_meta_fluff",
            title="Supplemental Context Hygiene Notes",
            category="CORE",
            body=(
                "- Never treat an exploratory question as a commitment.\n"
                "- Do not promote exploratory questions into preferences.\n"
                "- Never fabricate precision or pad with fluff.\n"
                "- Distinguish confirmed facts from guesses."
            ),
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )

    analysis = analyze_corpus(reg)
    assert analysis["active_count"] == 3
    assert analysis["boilerplate_count"] == 1
    assert any(
        {s["record_a"], s["record_b"]} == {"rec_kbd_1", "rec_kbd_2"}
        for s in analysis["merge_suggestions"]
    )
    assert any(
        f["kind"] == "META_BOILERPLATE" for f in analysis["record_hygiene"]["rec_meta_fluff"]
    )

    merged = merge_records(
        reg,
        ["rec_kbd_1", "rec_kbd_2"],
        target_title="Orbital65 Keyboard Hardware & Wireless Driver",
        target_category="HARDWARE",
    )
    assert merged["primary_id"] == "rec_kbd_1"
    assert merged["absorbed_ids"] == ["rec_kbd_2"]

    primary = reg.get_record("rec_kbd_1")
    absorbed = reg.get_record("rec_kbd_2")
    assert primary is not None and absorbed is not None
    assert absorbed["status"] == RecordStatus.SUPERSEDED.value
    assert absorbed["destination_eligible"] is False
    # Deduplicated identical bullet + stripped robotic tag prefixes
    assert primary["body"].count("Orbital65 wireless keyboard") == 1
    assert "[Confirmed]" not in primary["body"]
    assert "audio-reactive LED latency" in primary["body"]

    # Clean voice-friendly compilation (no Date/Period header, no [Confirmed] tags, briefing has real topics)
    compile_memory(reg, include_index=False)
    arts = load_compiled_artifacts(reg)
    kbd_log = next(a for a in arts if a.logical_id == "rec_kbd_1")
    assert "Date/Period:" not in kbd_log.body
    assert "[Confirmed]" not in kbd_log.body
    briefing = next(a for a in arts if a.artifact_kind == "briefing")
    assert "Orbital65 Keyboard Hardware" in briefing.body


def test_strip_robotic_tag_prefixes() -> None:
    raw = "- [Confirmed] (2026-11) Prefers typed Python.\n- [Constraint] Never leak tokens.\n- Regular bullet."
    cleaned = strip_robotic_tag_prefixes(raw)
    assert cleaned == "- Prefers typed Python.\n- Never leak tokens.\n- Regular bullet."


def test_deep_local_projects_harvester(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    repo = fake_home / "Projects" / "stellar-cli"
    (repo / ".git").mkdir(parents=True)
    (repo / "pyproject.toml").write_text('[project]\nname = "stellar-cli"\n', encoding="utf-8")
    (repo / "README.md").write_text(
        "# Stellar CLI\n\nFast local-first CLI tool for astronomy calculations.\n",
        encoding="utf-8",
    )
    (repo / ".env").write_text("SECRET_KEY=sk-proj-supersecret1234567890", encoding="utf-8")

    det = detect_local_sources(home=fake_home)
    proj_src = next(s for s in det["local_sources"] if s["source_id"] == "local_projects")
    assert proj_src["found"] is True

    out_dir = tmp_path / "harvested"
    hres = harvest_local_sources(out_dir, sources=["local_projects"], home=fake_home)
    assert len(hres["written"]) == 1
    md = (out_dir / "local_local_projects.md").read_text(encoding="utf-8")
    assert "stellar-cli" in md
    assert "[Python]" in md
    assert "astronomy calculations" in md
    assert "supersecret" not in md


async def test_live_inspect_and_quarantine_to_memory_archive(
    tmp_db: Database, mock_server: RunningMockServer
) -> None:
    reg = KnowledgeRegistry(tmp_db)
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="keep_dossier",
            title="Current Active Context",
            category="CORE",
            body="Active curated context that should stay in sync.",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    compile_memory(reg, include_index=False)
    compiled_logs = [a for a in load_compiled_artifacts(reg) if a.artifact_kind == "log"]

    tok = mock_server.state.issue_token("acct_primary")
    sched = AccountRateScheduler(tmp_db, "acct_quarantine_test", min_interval_seconds=0.0)
    adapter = SandbarMCPAdapter(
        server_url=mock_server.mcp_url,
        scheduler=sched,
        bearer_token=tok["access_token"],
        allow_localhost_http=True,
        expected_mode=ExecutionMode.MOCK,
    )
    await adapter.discover_capabilities()

    # Seed Memory folder with 1 matching Note + 2 stale old Notes
    mem_folder = await adapter.create_folder("Memory", instruction="Memory logs")
    await adapter.create_log(
        title=compiled_logs[0].title,
        body=compiled_logs[0].body,
        folder_id=mem_folder.folder_id,
    )
    stale_1 = await adapter.create_log(
        title="OLD — Scattered Fragment 1",
        body="Old redundant context.",
        folder_id=mem_folder.folder_id,
    )
    stale_2 = await adapter.create_log(
        title="OLD — Scattered Fragment 2",
        body="Another old fragment.",
        folder_id=mem_folder.folder_id,
    )

    live_before = await inspect_live_memory_state(adapter, compiled_logs)
    assert len(live_before["in_sync"]) == 1
    assert len(live_before["stale_in_stream"]) == 2
    assert live_before["archive_count"] == 0

    # Quarantine ONLY the 2 stale notes into Memory Archive via official set_note_folder
    events: list[dict[str, object]] = []
    qres = await quarantine_logs_to_archive(
        adapter,
        artifact_ids=[stale_1.artifact_id, stale_2.artifact_id],
        progress_cb=lambda ev: events.append(ev),
    )
    assert qres["moved_count"] == 2
    assert qres["failed_count"] == 0
    assert len(events) == 2

    live_after = await inspect_live_memory_state(adapter, compiled_logs)
    assert len(live_after["in_sync"]) == 1
    assert len(live_after["stale_in_stream"]) == 0
    assert live_after["archive_count"] == 2


def test_v2_studio_ui_collect_merge_and_safety_guards(tmp_path: Path) -> None:
    data_dir = tmp_path / "studio_data"
    Database(data_dir / "stream_memory.db").close()
    app, csrf = create_staging_ui_app(data_dir)
    client = TestClient(app, base_url="http://127.0.0.1:4319")

    # Root redirects to /view and renders V2 Studio
    r_root = client.get("/", follow_redirects=False)
    assert r_root.status_code == 307
    r_view = client.get("/view")
    assert r_view.status_code == 200
    assert "Stream Memory Studio" in r_view.text
    assert "https://stream.sandbar.com" in r_view.text

    # Generate premade Max-Thinking prompt via UI API
    r_prompt = client.post(
        "/api/collect/prompt",
        json={"service_id": "chatgpt", "mode": "full"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r_prompt.status_code == 200
    assert "STREAM_MEMORY_EXPORT v1" in r_prompt.json()["prompt"]

    # Paste standardized content directly into Studio
    pasted = (
        "<!-- STREAM_MEMORY_EXPORT v1 | source: chatgpt | mode: full | date: 2026-11-24 -->\n"
        "# 00 — Display Setup\nCategory: HARDWARE\nStatus: ACTIVE\nObserved: 2026-11-24\n"
        "- [Confirmed] (2026-11) Prefers 27-inch 5K display at 120Hz.\n"
        "# 01 — Display Specs Delta\nCategory: HARDWARE\nStatus: ACTIVE\nObserved: 2026-11-24\n"
        "- [Confirmed] (2026-11) Requires full Apple Silicon HiDPI text clarity.\n"
        "<!-- END_STREAM_MEMORY_EXPORT -->"
    )
    r_paste = client.post(
        "/api/collect/paste",
        json={"content": pasted, "label": "chatgpt"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r_paste.status_code == 200
    assert r_paste.json()["records_parsed"] == 2

    # Merge the two overlapping records via Studio API
    st = client.get("/api/state").json()
    lids = [r["logical_id"] for r in st["records"]]
    assert len(lids) == 2
    r_merge = client.post(
        "/api/merge",
        json={
            "source_ids": lids,
            "target_title": "Display Hardware Preferences",
            "target_category": "HARDWARE",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert r_merge.status_code == 200
    assert r_merge.json()["word_count"] > 10

    # Mutating sync/quarantine endpoints MUST fail closed without confirm=true and CSRF
    assert client.post("/api/stream/sync", json={"confirm": True}).status_code == 403
    assert (
        client.post(
            "/api/stream/sync", json={"confirm": False}, headers={"X-CSRF-Token": csrf}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/stream/quarantine", json={"confirm": False}, headers={"X-CSRF-Token": csrf}
        ).status_code
        == 400
    )
