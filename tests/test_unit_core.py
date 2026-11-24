"""Unit tests for canonical registry, hashing, word count/Unicode, compiler, privacy, and reconciliation."""

from __future__ import annotations

from pathlib import Path

import pytest

from stream_memory_manager.capabilities import default_offline_documented_capabilities
from stream_memory_manager.compiler import (
    compile_memory,
    count_words_dual,
    load_compiled_artifacts,
    normalize_remote_text,
    semantic_split_log,
    validate_log_payload,
)
from stream_memory_manager.db import Database
from stream_memory_manager.ingestion import ingest_file
from stream_memory_manager.models import (
    EvidenceClass,
    ExecutionMode,
    InclusionDecision,
    MemoryRecordInput,
    PrivacyViolationError,
    RecordStatus,
    StreamMemoryError,
)
from stream_memory_manager.planner import ImportPlanner, ObservedRemoteState
from stream_memory_manager.privacy import (
    assert_record_exportable,
    evaluate_registry_privacy,
    scan_text_privacy,
)
from stream_memory_manager.reconciliation import reconcile_registry
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import redact_secrets


def test_stable_logical_id_survives_title_and_body_revisions(tmp_db: Database) -> None:
    reg = KnowledgeRegistry(tmp_db)
    r1 = reg.upsert_record(
        MemoryRecordInput(
            logical_id="civic_entity_res",
            title="Entity Resolution Draft",
            category="CIVIC",
            body="Initial draft covering Bioguide joins.",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    assert r1["action"] == "created"
    assert r1["revision_number"] == 1

    # Re-ingesting identical normalized content is idempotent (no new revision)
    r1_dup = reg.upsert_record(
        MemoryRecordInput(
            logical_id="civic_entity_res",
            title="Entity Resolution Draft",
            category="CIVIC",
            body="Initial draft covering Bioguide joins.\r\n",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    assert r1_dup["action"] == "unchanged"
    assert r1_dup["revision_number"] == 1

    # Updating title AND body retains identical logical_id and increments revision
    r2 = reg.upsert_record(
        MemoryRecordInput(
            logical_id="civic_entity_res",
            title="Political Knowledge Graph Entity Reconciliation",
            category="CIVIC",
            body="Updated design separating canonical persons from candidacies.",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    assert r2["action"] == "revised"
    assert r2["revision_number"] == 2
    revs = reg.list_revisions("civic_entity_res")
    assert len(revs) == 2
    assert revs[0]["superseded_by_revision_id"] == "civic_entity_res@r2"
    rec = reg.get_record("civic_entity_res")
    assert rec is not None
    assert rec["logical_id"] == "civic_entity_res"
    assert rec["title"] == "Political Knowledge Graph Entity Reconciliation"


def test_adversarial_word_count_unicode_and_semantic_split() -> None:
    # Zero-width spaces, NBSP, ideographic spaces, combining marks, slashes, unbroken strings
    tricky_title = "CORE — Unicode\u00a0Check"
    tricky_body = "alpha\u200bbeta\u3000gamma a/b/c/d e\u0301 " + ("x" * 180)
    ws, cons = count_words_dual(tricky_title, tricky_body)
    assert ws >= 6
    assert cons > ws  # Slashes + 180-char unbroken string penalized conservatively!

    # Reject oversize log payload before write
    big_body = " ".join(f"word{i}" for i in range(950))
    with pytest.raises(StreamMemoryError, match="exceeds word ceiling"):
        validate_log_payload("Oversize Title", big_body, max_words=900)

    # Semantic split NEVER silently truncates; preserves every distinct marker across parts
    paragraphs = [
        f"## Section {i}\n\n" + " ".join(f"token_{i}_{j}" for j in range(120)) for i in range(12)
    ]
    long_doc = "\n\n".join(paragraphs)
    parts = semantic_split_log("ENGINEERING — Deep Architecture", long_doc, max_words=450)
    assert len(parts) >= 4
    rejoined = "\n".join(body for _, body in parts)
    for i in range(12):
        assert f"token_{i}_0" in rejoined
        assert f"token_{i}_119" in rejoined
    for title, body in parts:
        _, c = validate_log_payload(title, body, max_words=450)
        assert c <= 450
        assert "(Part " in title
        assert "Series note:" in body


def test_normalization_policy_allows_crlf_but_rejects_substantive_drift() -> None:
    a = normalize_remote_text("Line 1  \r\nLine 2\t\r\n\r\n")
    b = normalize_remote_text("Line 1\nLine 2")
    assert a == b
    assert normalize_remote_text("Line 1\nLine 2!") != b


def test_privacy_engine_hard_blocks_and_adhd_nuance(tmp_db: Database) -> None:
    reg = KnowledgeRegistry(tmp_db)
    # 1. Allowed ADHD self-report nuance (Section 10.2)
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="adhd_self_report",
            title="Focus and Evaluation Interest",
            category="PERSONAL",
            body="User has self-reported ADHD-related focus concerns and interest in evaluation; explicitly not a formal ADHD diagnosis.",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    # 2. Hard-blocked exact balance + secret + operational Tailscale host
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="leaked_finance",
            title="Finance Leak",
            category="PERSONAL",
            body="Checking account balance is $42,150.00 and token sk-proj-1234567890abcdef1234567890.",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="leaked_infra",
            title="Server Host",
            category="INFRASTRUCTURE",
            body="Connect via homelab.tail1234.ts.net and https://ntfy.sh/secret_topic_9999.",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )

    report = evaluate_registry_privacy(reg)
    blocked_ids = {item["logical_id"] for item in report["hard_blocked"]}
    assert blocked_ids == {"leaked_finance", "leaked_infra"}
    clean_ids = {item["logical_id"] for item in report["approved_clean"]}
    assert "adhd_self_report" in clean_ids

    # Assert export gate fails closed for blocked records
    leaked_rec = reg.get_record("leaked_finance")
    assert leaked_rec is not None
    with pytest.raises(PrivacyViolationError):
        assert_record_exportable(leaked_rec)

    # Formal diagnosis claim without negation triggers REVIEW flag
    diag_findings = scan_text_privacy("Health", "User was formally diagnosed with ADHD in 2025.")
    assert any(f.rule_id == "adhd_formal_diagnosis_claim" for f in diag_findings)


def test_temporal_and_supersession_reconciliation(tmp_db: Database) -> None:
    reg = KnowledgeRegistry(tmp_db)
    # Older record vs newer higher-evidence record on same canonical subject
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="old_kbd",
            title="Keyboard Driver Notes",
            category="HARDWARE",
            canonical_subject="Orbital65 Wireless Protocol",
            body="Static guess: wireless dongle uses page 0xFF00.",
            evidence_class=EvidenceClass.INFERRED,
            effective_date="2026-08-23",
            observed_date="2026-08-23",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="new_kbd",
            title="Keyboard Physical Readback",
            category="HARDWARE",
            canonical_subject="Orbital65 Wireless Protocol",
            body="Physical USB testing established wireless dongle PID 0xBEEF uses report page 0xFF60.",
            evidence_class=EvidenceClass.ARTIFACT_INSPECTED,
            effective_date="2026-11-06",
            observed_date="2026-11-06",
            last_confirmed_date="2026-11-06",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )

    rec_summary = reconcile_registry(reg)
    assert any(
        s["superseded"] == "old_kbd" and s["by"] == "new_kbd"
        for s in rec_summary["superseded_applied"]
    )
    old_row = reg.get_record("old_kbd")
    assert old_row is not None
    assert old_row["status"] == RecordStatus.SUPERSEDED.value
    assert old_row["destination_eligible"] is False


def test_deterministic_compilation_and_plan_hashing(tmp_db: Database) -> None:
    reg = KnowledgeRegistry(tmp_db)
    reg.upsert_record(
        MemoryRecordInput(
            logical_id="rec_a",
            title="Alpha Context",
            category="CORE",
            body="Alpha durable personal context.",
            inclusion_decision=InclusionDecision.APPROVED,
        )
    )
    c1 = compile_memory(reg)
    c2 = compile_memory(reg)
    assert c1["manifest_hash"] == c2["manifest_hash"]
    assert c1["folder_instruction_chars"] <= 140

    caps = default_offline_documented_capabilities()
    planner = ImportPlanner(tmp_db, reg)
    p1 = planner.build_plan(
        mode=ExecutionMode.DRY_RUN,
        account_binding_hash="bind_001",
        capabilities=caps,
        remote_state=ObservedRemoteState(is_offline_assumption=True),
    )
    p2 = planner.build_plan(
        mode=ExecutionMode.DRY_RUN,
        account_binding_hash="bind_001",
        capabilities=caps,
        remote_state=ObservedRemoteState(is_offline_assumption=True),
    )
    assert p1["plan_id"] == p2["plan_id"]
    assert len(load_compiled_artifacts(reg)) >= 2


def test_secret_redaction_and_markdown_json_ingestion(tmp_db: Database, tmp_path: Path) -> None:
    dirty = (
        "Authorization: Bearer super_secret_token_1234567890 and refresh_token=rt_abcdef1234567890"
    )
    cleaned = redact_secrets(dirty)
    assert "super_secret_token" not in cleaned
    assert "rt_abcdef1234567890" not in cleaned
    assert "[REDACTED]" in cleaned

    md_file = tmp_path / "notes.md"
    md_file.write_text(
        "# Topic One\n\nClean synthetic engineering note.\n\n# Topic Two\n\nSecond note.\n",
        encoding="utf-8",
    )
    reg = KnowledgeRegistry(tmp_db)
    res = ingest_file(reg, md_file, default_approve=True)
    assert res["records_parsed"] == 2
    assert res["created"] == 2

    # Refuses private appendix filename automatically
    priv_file = tmp_path / "private_appendix_secret.md"
    priv_file.write_text("# Secret\n\nDo not import.\n", encoding="utf-8")
    with pytest.raises(StreamMemoryError, match="private-review appendix"):
        ingest_file(reg, priv_file)
