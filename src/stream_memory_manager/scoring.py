"""MemoryVault-inspired utility, confidence, importance scoring, and token-budgeted context packing."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from stream_memory_manager.models import EvidenceClass, RecordStatus

CERTAINTY_KEYWORDS = (
    "verified",
    "confirmed",
    "exact",
    "measured",
    "physical",
    "official",
    "passed",
    "lrat",
    "readback",
    "audited",
)
HEDGE_KEYWORDS = (
    "maybe",
    "might",
    "perhaps",
    "guess",
    "probably",
    "unsure",
    "tentative",
    "unconfirmed",
    "unknown",
    "possibly",
)
IMPORTANCE_KEYWORDS = (
    "goal",
    "priority",
    "priorities",
    "directive",
    "philosophy",
    "preference",
    "preferences",
    "operating",
    "architecture",
    "decision",
    "objective",
    "active",
    "constraint",
    "standing",
)

EVIDENCE_BASE_CONFIDENCE: dict[str, float] = {
    EvidenceClass.USER_DIRECTED.value: 0.95,
    EvidenceClass.INDEPENDENTLY_VERIFIED.value: 0.94,
    EvidenceClass.ARTIFACT_INSPECTED.value: 0.90,
    EvidenceClass.USER_CONFIRMED.value: 0.84,
    EvidenceClass.AGENT_REPORTED.value: 0.68,
    EvidenceClass.PROPOSED.value: 0.62,
    EvidenceClass.HISTORICAL.value: 0.58,
    EvidenceClass.INFERRED.value: 0.48,
    EvidenceClass.UNKNOWN.value: 0.32,
    EvidenceClass.SUPERSEDED.value: 0.12,
}

STATUS_IMPORTANCE_WEIGHT: dict[str, float] = {
    RecordStatus.ACTIVE.value: 1.00,
    RecordStatus.PROPOSED.value: 0.80,
    RecordStatus.DORMANT.value: 0.65,
    RecordStatus.HISTORICAL.value: 0.58,
    RecordStatus.DRAFT.value: 0.40,
    RecordStatus.ARCHIVED.value: 0.25,
    RecordStatus.SUPERSEDED.value: 0.10,
}

CATEGORY_BASE_IMPORTANCE: dict[str, float] = {
    "CORE": 0.96,
    "PREFERENCES": 0.88,
    "CURRENT": 0.86,
    "ENGINEERING": 0.82,
    "PERSONAL": 0.78,
    "ACADEMICS": 0.76,
    "PROJECTS": 0.74,
    "CIVIC": 0.74,
    "INFRASTRUCTURE": 0.72,
    "HARDWARE": 0.70,
    "RESEARCH": 0.68,
    "SOFTWARE": 0.68,
    "WORKFLOWS": 0.66,
    "HISTORY": 0.55,
}

ISO_DATE_RE = re.compile(r"\b((?:19|20)\d{2})-(\d{2})(?:-(\d{2}))?\b")


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _count_keyword_hits(text: str, keywords: tuple[str, ...]) -> int:
    hits = 0
    for kw in keywords:
        if re.search(rf"\b{re.escape(kw)}\b", text):
            hits += 1
    return hits


def _parse_reference_date(record: dict[str, Any]) -> date | None:
    for field in ("last_confirmed_date", "effective_date", "observed_date", "updated_at"):
        val = str(record.get(field) or "")
        m = ISO_DATE_RE.search(val)
        if m:
            yr, mo = int(m.group(1)), min(12, max(1, int(m.group(2))))
            dy = min(28, max(1, int(m.group(3)))) if m.group(3) else 15
            try:
                return date(yr, mo, dy)
            except ValueError:
                continue
    return None


@dataclass(frozen=True)
class MemoryScore:
    logical_id: str
    utility: float
    confidence: float
    importance: float
    freshness: float
    tier: str  # "BRIEFING" | "CORE_LOG" | "DETAIL_LOG" | "ARCHIVE"
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_id": self.logical_id,
            "utility": self.utility,
            "confidence": self.confidence,
            "importance": self.importance,
            "freshness": self.freshness,
            "tier": self.tier,
            "reasons": list(self.reasons),
        }


def score_record(
    record: dict[str, Any],
    *,
    reference_date: date | None = None,
) -> MemoryScore:
    """Compute transparent MemoryVault-style utility, confidence, importance, and freshness scores."""
    ref_day = reference_date or date.today()
    lid = str(record.get("logical_id", ""))
    cat = str(record.get("category", "CORE")).upper()
    status = str(record.get("status", RecordStatus.ACTIVE.value)).upper()
    ev = str(record.get("evidence_class", EvidenceClass.USER_CONFIRMED.value)).upper()
    title = str(record.get("title", ""))
    body = str(record.get("body", ""))
    blob = f"{title}\n{body}".lower()

    reasons: list[str] = []

    # 1. Confidence from evidence class + certainty vs hedge lexical signals
    conf = EVIDENCE_BASE_CONFIDENCE.get(ev, 0.70)
    certainty_hits = _count_keyword_hits(blob, CERTAINTY_KEYWORDS)
    hedge_hits = _count_keyword_hits(blob, HEDGE_KEYWORDS)
    conf += min(0.08, certainty_hits * 0.02)
    conf -= min(0.14, hedge_hits * 0.025)
    conf = _clamp01(conf)
    if certainty_hits >= 2:
        reasons.append(f"high_certainty_signals({certainty_hits})")
    if hedge_hits >= 3:
        reasons.append(f"hedged_or_uncertain_language({hedge_hits})")

    # 2. Importance from category, status, and standing-priority cues
    base_imp = CATEGORY_BASE_IMPORTANCE.get(cat, 0.65)
    imp_hits = _count_keyword_hits(blob, IMPORTANCE_KEYWORDS)
    imp = base_imp + min(0.12, imp_hits * 0.02)
    imp *= STATUS_IMPORTANCE_WEIGHT.get(status, 0.70)
    if len(body.split()) < 25:
        imp *= 0.80
        reasons.append("very_short_record")
    imp = _clamp01(imp)

    # 3. Freshness (half-life ~180 days; durable CORE/PREFERENCES decay slower)
    rec_date = _parse_reference_date(record)
    if rec_date is None:
        freshness = 0.75
    else:
        age_days = max(0, (ref_day - rec_date).days)
        half_life = 365.0 if cat in ("CORE", "PREFERENCES", "ENGINEERING") else 180.0
        freshness = _clamp01(math.exp(-math.log(2) * (age_days / half_life)))

    # 4. Combined utility (weighted geometric-linear blend)
    utility = _clamp01(0.45 * imp + 0.35 * conf + 0.20 * freshness)
    if not record.get("destination_eligible", True) or status == RecordStatus.SUPERSEDED.value:
        utility *= 0.15
        reasons.append("ineligible_or_superseded")

    if utility >= 0.82 and status == RecordStatus.ACTIVE.value:
        tier = "BRIEFING"
    elif utility >= 0.68:
        tier = "CORE_LOG"
    elif utility >= 0.45:
        tier = "DETAIL_LOG"
    else:
        tier = "ARCHIVE"

    return MemoryScore(
        logical_id=lid,
        utility=round(utility, 3),
        confidence=round(conf, 3),
        importance=round(imp, 3),
        freshness=round(freshness, 3),
        tier=tier,
        reasons=tuple(reasons),
    )


def _first_summary_sentence(body: str, max_words: int = 32) -> str:
    """Extract the highest-signal compact summary snippet from a record body."""
    lines = [
        ln.strip().lstrip("*-• ").strip()
        for ln in body.splitlines()
        if ln.strip()
        and not ln.strip().startswith("#")
        and not ln.strip().startswith("**")
        and not ln.strip().startswith("```")
    ]
    if not lines:
        return ""
    text = " ".join(lines[:3])
    words = text.split()
    if len(words) <= max_words:
        return text
    return " ".join(words[:max_words]).rstrip(",;:") + "..."


def pack_briefing_context(
    records: list[dict[str, Any]],
    *,
    max_words: int = 220,
    max_entries: int = 8,
    folder_name: str = "Memory",
    reference_date: date | None = None,
) -> dict[str, Any]:
    """MemoryVault-inspired greedy utility context packer for Sandbar Stream's every-turn Briefing."""
    eligible = [
        r
        for r in records
        if r.get("destination_eligible")
        and str(r.get("inclusion_decision")) == "APPROVED"
        and str(r.get("status")) not in ("SUPERSEDED", "DRAFT", "ARCHIVED")
    ]
    scored = [(score_record(r, reference_date=reference_date), r) for r in eligible]
    scored.sort(key=lambda pair: (pair[0].utility, pair[1]["logical_id"]), reverse=True)

    header = (
        f"Persistent user context lives in the `{folder_name}` folder. "
        "Retrieve full Logs when relevant; prefer newer corrections; separate built vs proposed."
    )
    used_words = len(header.split())
    lines: list[str] = [header]
    selected_ids: list[str] = []
    skipped = 0

    for _sc, rec in scored:
        if len(selected_ids) >= max_entries:
            skipped += 1
            continue
        snippet = _first_summary_sentence(str(rec.get("body", "")), max_words=28)
        if not snippet:
            continue
        entry_line = f"- {rec['category']} ({rec['title']}): {snippet}"
        entry_words = len(entry_line.split())
        if used_words + entry_words > max_words:
            # Allow one trimmed entry if >= 18 words remain (MemoryVault partial-fit pattern)
            remaining = max_words - used_words
            if remaining >= 18 and not selected_ids:
                trimmed = " ".join(entry_line.split()[: remaining - 1]) + "..."
                lines.append(trimmed)
                used_words += len(trimmed.split())
                selected_ids.append(str(rec["logical_id"]))
            else:
                skipped += 1
            continue
        lines.append(entry_line)
        used_words += entry_words
        selected_ids.append(str(rec["logical_id"]))

    return {
        "briefing_text": "\n".join(lines),
        "word_count": used_words,
        "selected_logical_ids": selected_ids,
        "skipped_over_budget": skipped,
    }
