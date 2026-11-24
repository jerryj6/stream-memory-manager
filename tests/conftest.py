"""Shared pytest fixtures: synthetic test personas ONLY (zero private data) + production-network blocker."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from stream_memory_manager.clock import FakeClock
from stream_memory_manager.db import Database
from stream_memory_manager.mock_server import MockSandbarState, MockServerConfig, RunningMockServer
from stream_memory_manager.models import (
    EvidenceClass,
    InclusionDecision,
    MemoryRecordInput,
    PrivacyClassification,
    RecordStatus,
)
from stream_memory_manager.registry import KnowledgeRegistry

LOCALHOST_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", ""})


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Physically block any non-localhost TCP connection during automated tests (Section 28)."""
    real_connect = socket.socket.connect

    def _guarded_connect(self: socket.socket, address: Any) -> Any:
        if isinstance(address, tuple) and len(address) >= 1:
            host = str(address[0])
            if host not in LOCALHOST_HOSTS:
                raise RuntimeError(f"Blocked external network call during test suite to {host!r}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)


@pytest.fixture
def tmp_db(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "data" / "stream_memory.db")
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock(initial_epoch=1_795_400_000.0, initial_monotonic=1000.0)


@pytest.fixture
def mock_server() -> Iterator[RunningMockServer]:
    state = MockSandbarState(MockServerConfig())
    with RunningMockServer(state) as srv:
        yield srv


def seed_synthetic_records(registry: KnowledgeRegistry, *, count: int = 5) -> list[str]:
    """Populate strictly synthetic fictional records (Alex Mercer) for isolated testing."""
    samples = [
        MemoryRecordInput(
            logical_id="syn_core_instructions",
            title="AI Operating Instructions",
            category="CORE",
            body="Apply dated context naturally. Prefer newer explicit user corrections over older records. Separate proposed architecture from implemented systems.",
            evidence_class=EvidenceClass.USER_DIRECTED,
            effective_date="2026-11-01",
            observed_date="2026-11-20",
            last_confirmed_date="2026-11-20",
            search_aliases=["operating instructions", "voice behavior", "epistemic rules"],
            inclusion_decision=InclusionDecision.APPROVED,
        ),
        MemoryRecordInput(
            logical_id="syn_academics",
            title="Education and Policy Studies",
            category="ACADEMICS",
            body="Alex Mercer is studying Public Policy at Northern State University, focusing on regulatory law and civic technology.",
            evidence_class=EvidenceClass.USER_CONFIRMED,
            effective_date="2026-09-01",
            observed_date="2026-11-20",
            last_confirmed_date="2026-11-20",
            search_aliases=["Northern State University", "public policy", "regulatory law"],
            inclusion_decision=InclusionDecision.APPROVED,
        ),
        MemoryRecordInput(
            logical_id="syn_project_graph",
            title="Civic Ledger Knowledge Graph",
            category="CIVIC",
            body="Proposed bitemporal event-sourced ledger separating effective time from observation time. Not yet deployed to production; mobile client uses sample JSON only.",
            status=RecordStatus.PROPOSED,
            evidence_class=EvidenceClass.PROPOSED,
            effective_date="2026-11-18",
            observed_date="2026-11-20",
            last_confirmed_date="2026-11-20",
            search_aliases=["bitemporal", "civic ledger", "sample JSON"],
            inclusion_decision=InclusionDecision.APPROVED,
        ),
        MemoryRecordInput(
            logical_id="syn_hardware_kbd",
            title="Orbital65 Mechanical Keyboard Port",
            category="HARDWARE",
            body="Physical USB HID readback on macOS confirmed wireless dongle PID 0xBEEF uses report page 0xFF60 rather than static assumption 0xFF00.",
            evidence_class=EvidenceClass.ARTIFACT_INSPECTED,
            effective_date="2026-11-05",
            observed_date="2026-11-20",
            last_confirmed_date="2026-11-20",
            search_aliases=["Orbital65", "macOS HID", "wireless dongle"],
            inclusion_decision=InclusionDecision.APPROVED,
        ),
        MemoryRecordInput(
            logical_id="syn_quant_research",
            title="Preregistered Equity Research Standards",
            category="RESEARCH",
            body="Abandoned early overfit bots. Current workbench enforces point-in-time filings and explicit trade_ready: false gating with zero autonomous trading.",
            evidence_class=EvidenceClass.INDEPENDENTLY_VERIFIED,
            effective_date="2026-10-15",
            observed_date="2026-11-20",
            last_confirmed_date="2026-11-20",
            search_aliases=["trade_ready", "preregistered", "point-in-time"],
            inclusion_decision=InclusionDecision.APPROVED,
        ),
    ]
    ids: list[str] = []
    for idx in range(count):
        if idx < len(samples):
            rec = samples[idx]
        else:
            rec = MemoryRecordInput(
                logical_id=f"syn_extra_{idx:03d}",
                title=f"Synthetic Topic {idx:03d}",
                category="ENGINEERING",
                body=f"Self-contained synthetic memory record number {idx} covering deterministic testing invariants and reliable state transitions.",
                evidence_class=EvidenceClass.USER_CONFIRMED,
                effective_date="2026-11-01",
                observed_date="2026-11-20",
                search_aliases=[f"topic-{idx}", "synthetic"],
                privacy_classification=PrivacyClassification.PERSONAL_APPROVED,
                inclusion_decision=InclusionDecision.APPROVED,
            )
        registry.upsert_record(rec)
        ids.append(rec.logical_id)
    return ids
