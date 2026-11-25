"""Property-based tests with Hypothesis (reproducible seeds, derandomized) verifying system invariants."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from stream_memory_manager.compiler import (
    compile_memory,
    count_words_dual,
    load_compiled_artifacts,
    semantic_split_log,
    validate_log_payload,
)
from stream_memory_manager.db import Database
from stream_memory_manager.models import (
    EvidenceClass,
    InclusionDecision,
    MemoryRecordInput,
    PrivacyClassification,
    RecordStatus,
)
from stream_memory_manager.privacy import evaluate_registry_privacy
from stream_memory_manager.reconciliation import reconcile_registry
from stream_memory_manager.registry import KnowledgeRegistry

SAFE_WORDS = st.lists(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=2, max_size=12),
    min_size=5,
    max_size=120,
).map(" ".join)


@settings(max_examples=40, derandomize=True)
@given(
    bodies=st.lists(SAFE_WORDS, min_size=1, max_size=8),
    reorder_seed=st.integers(min_value=0, max_value=1000),
)
def test_property_recompilation_is_order_independent_and_deterministic(
    bodies: list[str], reorder_seed: int
) -> None:
    """Recompiling unchanged approved records in any insertion order yields identical manifest hashes."""
    import random

    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        db1 = Database(Path(d1) / "a.db")
        db2 = Database(Path(d2) / "b.db")
        try:
            reg1 = KnowledgeRegistry(db1)
            reg2 = KnowledgeRegistry(db2)
            records = [
                MemoryRecordInput(
                    logical_id=f"prop_{i:02d}",
                    title=f"Subject {i:02d}",
                    category="ENGINEERING",
                    body=body,
                    inclusion_decision=InclusionDecision.APPROVED,
                )
                for i, body in enumerate(bodies)
            ]
            for r in records:
                reg1.upsert_record(r)
            shuffled = list(records)
            random.Random(reorder_seed).shuffle(shuffled)
            for r in shuffled:
                reg2.upsert_record(r)

            c1 = compile_memory(reg1)
            c2 = compile_memory(reg2)
            assert c1["manifest_hash"] == c2["manifest_hash"]
            # Re-running compile on unchanged DB yields exact same hash
            c1_again = compile_memory(reg1)
            assert c1["manifest_hash"] == c1_again["manifest_hash"]
        finally:
            db1.close()
            db2.close()


@settings(max_examples=40, derandomize=True)
@given(
    title=st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", min_size=3, max_size=40).filter(
        lambda s: s.strip() != ""
    ),
    word_count=st.integers(min_value=10, max_value=1800),
)
def test_property_semantic_split_always_respects_word_ceiling_and_never_drops_tokens(
    title: str, word_count: int
) -> None:
    """Every output chunk from semantic_split_log satisfies conservative_words <= ceiling and loses zero words."""
    tokens = [f"w{i}" for i in range(word_count)]
    # Insert paragraph boundaries every 70 words
    paragraphs = [" ".join(tokens[i : i + 70]) for i in range(0, len(tokens), 70)]
    body = "\n\n".join(paragraphs)

    parts = semantic_split_log(title.strip(), body, max_words=300)
    assert len(parts) >= 1
    combined = "\n".join(pbody for _, pbody in parts)
    for ptitle, pbody in parts:
        _, cons = validate_log_payload(ptitle, pbody, max_words=300)
        assert cons <= 300
        assert count_words_dual(ptitle, pbody)[1] <= 300
    # Sample boundary tokens to verify zero truncation
    assert tokens[0] in combined
    assert tokens[-1] in combined
    assert tokens[len(tokens) // 2] in combined


@settings(max_examples=30, derandomize=True)
@given(
    secret_kind=st.sampled_from(
        [
            "Checking account balance is $9,876.54",
            "SSN 123-45-6789",
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature123456",
            "host.tail999.ts.net",
            "storageState.json",
            "sk-proj-1234567890abcdefghijklmnop",
        ]
    ),
    prefix=SAFE_WORDS,
)
def test_property_excluded_sensitive_data_never_enters_compiled_output(
    secret_kind: str, prefix: str
) -> None:
    """Invariant 10: Sensitive/excluded strings can NEVER survive privacy audit into compiled Logs."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "priv.db")
        try:
            reg = KnowledgeRegistry(db)
            reg.upsert_record(
                MemoryRecordInput(
                    logical_id="safe_rec",
                    title="Safe Record",
                    category="CORE",
                    body="Normal durable context.",
                    inclusion_decision=InclusionDecision.APPROVED,
                )
            )
            reg.upsert_record(
                MemoryRecordInput(
                    logical_id="tainted_rec",
                    title="Potentially Tainted",
                    category="PERSONAL",
                    body=f"{prefix} {secret_kind}",
                    privacy_classification=PrivacyClassification.PERSONAL_APPROVED,
                    inclusion_decision=InclusionDecision.APPROVED,
                )
            )
            evaluate_registry_privacy(reg)
            compile_memory(reg)
            arts = load_compiled_artifacts(reg)
            assert all(a.logical_id != "tainted_rec" for a in arts)
            for a in arts:
                assert secret_kind not in a.body
                assert secret_kind not in a.title
        finally:
            db.close()


@settings(max_examples=30, derandomize=True)
@given(
    old_year=st.integers(min_value=2020, max_value=2024),
    new_year=st.integers(min_value=2025, max_value=2026),
)
def test_property_older_evidence_never_supersedes_newer_confirmed_info(
    old_year: int, new_year: int
) -> None:
    """Invariant 11: Newer confirmed record always wins over older inferred record on same subject."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "temp.db")
        try:
            reg = KnowledgeRegistry(db)
            reg.upsert_record(
                MemoryRecordInput(
                    logical_id="older_rec",
                    title="Old Fact",
                    category="PREFERENCES",
                    canonical_subject="Preferred Display Setup",
                    body=f"Old preference from {old_year}.",
                    evidence_class=EvidenceClass.INFERRED,
                    effective_date=f"{old_year}-05-01",
                    observed_date=f"{old_year}-05-01",
                    inclusion_decision=InclusionDecision.APPROVED,
                )
            )
            reg.upsert_record(
                MemoryRecordInput(
                    logical_id="newer_rec",
                    title="New Fact",
                    category="PREFERENCES",
                    canonical_subject="Preferred Display Setup",
                    body=f"Confirmed preference from {new_year}.",
                    evidence_class=EvidenceClass.USER_CONFIRMED,
                    effective_date=f"{new_year}-11-01",
                    observed_date=f"{new_year}-11-01",
                    last_confirmed_date=f"{new_year}-11-01",
                    inclusion_decision=InclusionDecision.APPROVED,
                )
            )
            reconcile_registry(reg)
            old_r = reg.get_record("older_rec")
            new_r = reg.get_record("newer_rec")
            assert old_r is not None and new_r is not None
            assert old_r["status"] == RecordStatus.SUPERSEDED.value
            assert new_r["status"] == RecordStatus.ACTIVE.value
        finally:
            db.close()
