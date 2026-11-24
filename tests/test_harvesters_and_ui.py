"""Tests for MemoryVault-inspired scoring, universal harvesters, numbered master parser, and localhost staging UI."""

from __future__ import annotations

import json
import zipfile
from datetime import date
from pathlib import Path

from starlette.testclient import TestClient

from stream_memory_manager.compiler import load_compiled_artifacts
from stream_memory_manager.db import Database
from stream_memory_manager.harvesters import (
    build_web_extraction_kit,
    detect_local_sources,
    harvest_local_sources,
    parse_web_export_to_markdown,
)
from stream_memory_manager.ingestion import ingest_file
from stream_memory_manager.models import (
    EvidenceClass,
    InclusionDecision,
    MemoryRecordInput,
    RecordStatus,
)
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.scoring import pack_briefing_context, score_record
from stream_memory_manager.web_ui import create_staging_ui_app


def test_memoryvault_style_scoring_and_context_packing(tmp_db: Database) -> None:
    reg = KnowledgeRegistry(tmp_db)
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="core_directive",
            title="Operating Instructions and Priority Directive",
            category="CORE",
            body="Verified standing directive: prioritize primary sources, measured evidence, and direct answers across all active workflows.",
            status=RecordStatus.ACTIVE,
            evidence_class=EvidenceClass.USER_DIRECTED,
            effective_date="2026-11-23",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="old_guess",
            title="Tentative Idea",
            category="HISTORY",
            body="Maybe might perhaps guess an old unconfirmed thought.",
            status=RecordStatus.HISTORICAL,
            evidence_class=EvidenceClass.INFERRED,
            effective_date="2024-01-01",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    recs = reg.list_records()
    s_high = score_record(
        next(r for r in recs if r["logical_id"] == "core_directive"),
        reference_date=date(2026, 11, 24),
    )
    s_low = score_record(
        next(r for r in recs if r["logical_id"] == "old_guess"), reference_date=date(2026, 11, 24)
    )
    assert s_high.utility > s_low.utility
    assert s_high.confidence > s_low.confidence
    assert s_high.tier in ("BRIEFING", "CORE_LOG")

    packed = pack_briefing_context(recs, max_words=80, reference_date=date(2026, 11, 24))
    assert packed["word_count"] <= 80
    assert packed["selected_logical_ids"][0] == "core_directive"


def test_numbered_master_markdown_parser_preserves_sections_and_categories(
    tmp_db: Database, tmp_path: Path
) -> None:
    md = tmp_path / "master_context.md"
    md.write_text(
        "# PERSISTENT PERSONAL AND TECHNICAL CONTEXT\n\n"
        "# 00 — Receiving AI Operating Instructions\n\n"
        "* Apply context naturally.\n* Prefer newer corrections.\n\n"
        "# 04 — Agent-First Engineering Philosophy\n\n"
        "Systems should be agent-intuitive and resource-efficient.\n\n"
        "# 08 — Political Knowledge Graph Architecture\n\n"
        "**Status:** Proposed technical architecture.\n\n"
        "Use event sourcing and bitemporal modeling.\n",
        encoding="utf-8",
    )
    reg = KnowledgeRegistry(tmp_db)
    res = ingest_file(reg, md, default_approve=True)
    assert res["detected_format"] == "numbered_master_md"
    assert res["records_parsed"] == 3
    recs = {str(r["logical_id"]): r for r in reg.list_records()}
    assert any(
        r["category"] == "CORE" and r["evidence_class"] == "USER_DIRECTED" for r in recs.values()
    )
    assert any(r["category"] == "ENGINEERING" for r in recs.values())
    assert any(r["category"] == "CIVIC" and r["status"] == "PROPOSED" for r in recs.values())


def test_universal_local_harvesters_redact_secrets_and_skip_env_files(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    (fake_home / ".codex" / "sessions").mkdir(parents=True)
    (fake_home / ".codex" / "history.jsonl").write_text(
        json.dumps(
            {
                "session_id": "s1",
                "text": "Build local tool with token sk-proj-1234567890abcdefghijklmnop",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (fake_home / ".claude" / "memory").mkdir(parents=True)
    (fake_home / ".claude" / "memory" / "prefs.md").write_text(
        "Prefers clean Python CLI tools.\n", encoding="utf-8"
    )
    (fake_home / ".claude" / "memory" / ".env").write_text(
        "SECRET_KEY=never_read_this\n", encoding="utf-8"
    )
    (fake_home / "AGENTS.md").write_text("Global agent operating directive.\n", encoding="utf-8")

    det = detect_local_sources(home=fake_home)
    found_ids = {s["source_id"] for s in det["local_sources"] if s["found"]}
    assert {"codex", "claude_code", "global_instructions"}.issubset(found_ids)

    out_dir = tmp_path / "harvested"
    hres = harvest_local_sources(
        out_dir, sources=["codex", "claude_code", "global_instructions"], home=fake_home
    )
    assert len(hres["written"]) == 3
    codex_md = (out_dir / "local_codex.md").read_text(encoding="utf-8")
    assert "sk-proj-1234567890" not in codex_md
    assert "[REDACTED" in codex_md
    claude_md = (out_dir / "local_claude_code.md").read_text(encoding="utf-8")
    assert "never_read_this" not in claude_md
    assert "Prefers clean Python CLI tools" in claude_md


def test_dynamic_web_extraction_kit_and_official_export_parsers(tmp_path: Path) -> None:
    kit = build_web_extraction_kit(["chatgpt", "duck_ai", "t3_chat"])
    assert kit["selected_services"] == ["chatgpt", "duck_ai", "t3_chat"]
    assert kit["template_version"] == "stream_memory_export_v1"
    by_id = {p["service_id"]: p for p in kit["service_plans"]}
    assert len(by_id["chatgpt"]["prompts"]) == 1
    assert "MAX" in by_id["chatgpt"]["max_thinking_instruction"].upper()
    assert "<!-- STREAM_MEMORY_EXPORT v1" in by_id["chatgpt"]["prompts"][0]["prompt"]
    assert "<!-- END_STREAM_MEMORY_EXPORT -->" in by_id["chatgpt"]["prompts"][0]["prompt"]
    assert len(by_id["duck_ai"]["prompts"]) == 0  # Ephemeral: no fake cross-chat prompts!
    assert by_id["t3_chat"]["supports_official_export"] is True

    # Delta mode with minimal personalization slots (covered topics + next section number)
    delta_kit = build_web_extraction_kit(
        ["chatgpt"],
        mode="delta",
        covered_topics=["Personal Briefing", "Hardware Preferences"],
        start_section=36,
        reference_date="2026-11-24",
        extra_exclusions="Confidential NDA tasks",
    )
    delta_prompt = delta_kit["service_plans"][0]["prompts"][0]["prompt"]
    assert "DELTA ONLY" in delta_prompt
    assert "Personal Briefing; Hardware Preferences" in delta_prompt
    assert "# 36 —" in delta_prompt
    assert "Confidential NDA tasks" in delta_prompt

    # Verify standardized STREAM_MEMORY_EXPORT v1 reply (including ChatGPT Copy-button bold & \<!-- quirks)
    std_reply = tmp_path / "web_chatgpt_delta.md"
    std_reply.write_text(
        "\\<!-- STREAM_MEMORY_EXPORT v1 | source: chatgpt | mode: delta | date: 2026-11-24 -->\n\n"
        "# **36 — Standardized Delta Test**\n\n"
        "Category: ENGINEERING\\\n"
        "Status: ACTIVE\\\n"
        "Observed: 2026-11-24\n\n"
        "- [Confirmed] (2026-11) Prefers strict machine-parseable export templates.\n"
        "- [Constraint] Never store confidential NDA material.\n\n"
        "\\<!-- END_STREAM_MEMORY_EXPORT -->\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "std_test.db")
    try:
        reg = KnowledgeRegistry(db)
        ires = ingest_file(reg, std_reply)
        assert ires["detected_format"] == "numbered_master_md"
        assert ires["records_parsed"] == 1
        rec = reg.get_record("ctx_36_standardized_delta_test")
        assert rec is not None
        assert rec["title"] == "Standardized Delta Test"
        assert rec["category"] == "ENGINEERING"
        assert rec["observed_date"] == "2026-11-24"
        assert "STREAM_MEMORY_EXPORT" not in rec["body"]
    finally:
        db.close()

    # Test official ChatGPT ZIP export parsing
    zpath = tmp_path / "chatgpt_export.zip"
    sample_convos = [
        {
            "title": "System Architecture Chat",
            "mapping": {
                "n1": {
                    "message": {
                        "author": {"role": "user"},
                        "content": {
                            "parts": [
                                "Design a local-first memory tool without leaking sk-proj-1234567890abcdefghijklmnop"
                            ]
                        },
                    }
                }
            },
        }
    ]
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("conversations.json", json.dumps(sample_convos))
    out_md = tmp_path / "out_chatgpt.md"
    pres = parse_web_export_to_markdown(zpath, out_md)
    assert pres["service"] == "chatgpt"
    assert pres["conversations_digested"] == 1
    txt = out_md.read_text(encoding="utf-8")
    assert "System Architecture Chat" in txt
    assert "sk-proj-1234567890" not in txt


def test_localhost_staging_ui_security_review_edit_and_compile(tmp_path: Path) -> None:
    data_dir = tmp_path / "ui_data"
    db = Database(data_dir / "stream_memory.db")
    reg = KnowledgeRegistry(db)
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="ui_rec_01",
            title="UI Review Item",
            category="ENGINEERING",
            body="Clean synthetic record for staging UI test.",
            inclusion_decision=InclusionDecision.PENDING_REVIEW,
        )
    )
    db.close()

    app, csrf = create_staging_ui_app(data_dir)
    client = TestClient(app, base_url="http://127.0.0.1:4319")

    # Rejects DNS rebinding non-loopback Host header!
    bad_host = client.get("/api/state", headers={"Host": "evil.attacker.com"})
    assert bad_host.status_code == 403

    # Renders HTML cleanly
    html_res = client.get("/view")
    assert html_res.status_code == 200
    assert 'name="color-scheme" content="light dark"' in html_res.text
    assert 'closedby="any"' in html_res.text

    # Rejects POST without CSRF token
    no_csrf = client.post("/api/approve-clean", json={})
    assert no_csrf.status_code == 403

    # Approves cleanly with valid CSRF, edits inline creating rev 2, re-approves, and compiles
    ok_app = client.post("/api/approve-clean", json={}, headers={"X-CSRF-Token": csrf})
    assert ok_app.status_code == 200
    assert ok_app.json()["approved_count"] == 1

    ok_edit = client.post(
        "/api/edit",
        json={
            "logical_id": "ui_rec_01",
            "title": "UI Review Item Updated",
            "category": "ENGINEERING",
            "body": "Updated clean synthetic record saved from staging UI.",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert ok_edit.status_code == 200

    ok_dec = client.post(
        "/api/decide",
        json={"logical_id": "ui_rec_01", "decision": "APPROVED", "ack_sensitive": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert ok_dec.status_code == 200

    ok_comp = client.post("/api/compile", json={}, headers={"X-CSRF-Token": csrf})
    assert ok_comp.status_code == 200
    assert ok_comp.json()["compiled_log_count"] >= 1

    # Verify compiled logs in state API
    st = client.get("/api/state").json()
    assert len(st["records"]) == 1
    assert st["records"][0]["title"] == "UI Review Item Updated"
    assert st["records"][0]["score"]["utility"] > 0.5
    assert len(st["compiled"]) >= 1
    db2 = Database(data_dir / "stream_memory.db")
    try:
        arts = load_compiled_artifacts(KnowledgeRegistry(db2))
        assert any("UI Review Item Updated" in a.title for a in arts)
    finally:
        db2.close()


def test_extract_json_from_fastmcp_string_result_envelope() -> None:
    from types import SimpleNamespace

    from stream_memory_manager.mcp_adapter import _extract_json_from_tool_result

    wrapped = SimpleNamespace(
        structuredContent={
            "result": '{"id": "note_123", "title": "Hello", "searchIndexStatus": "indexed"}'
        },
        content=[],
    )
    parsed = _extract_json_from_tool_result(wrapped)
    assert parsed["id"] == "note_123"
    assert parsed["searchIndexStatus"] == "indexed"

    native = SimpleNamespace(
        structuredContent={"folders": [{"id": "f1", "title": "Memory"}]},
        content=[],
    )
    assert _extract_json_from_tool_result(native)["folders"][0]["title"] == "Memory"

    # Verify live Sandbar block-array `content` round-trip (title="" + title in content[0].text)
    from stream_memory_manager.mcp_adapter import _parse_remote_log

    live_item = {
        "id": "00000000-0000-4000-8000-000000000001",
        "type": "entry",
        "title": "",
        "folderId": "00000000-0000-4000-8000-000000000002",
        "lastUpdateUnixTs": 1795505952.997111,
        "content": [
            {"type": "text", "text": "CORE — Sample Title"},
            {"type": "text", "text": "Line 1"},
            {"type": "text", "text": ""},
            {"type": "text", "text": "- Bullet 1"},
        ],
    }
    parsed_log = _parse_remote_log(live_item)
    assert parsed_log.title == "CORE — Sample Title"
    assert parsed_log.body == "Line 1\n\n- Bullet 1"
    assert parsed_log.folder_id == "00000000-0000-4000-8000-000000000002"
