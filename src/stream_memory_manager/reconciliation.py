"""Cross-source reconciliation: deduplication, temporal/evidence precedence, and contradiction surfacing."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from stream_memory_manager.models import (
    EVIDENCE_RANK,
    EvidenceClass,
    RecordStatus,
    RelationType,
)
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import sha256_text

# Default tracked cross-source supersession/supplement rules are intentionally empty.
# Users can define optional owner-specific rules in gitignored `data/local_reconciliation_rules.json`.
KNOWN_SUPERSESSION_RULES: tuple[tuple[str, tuple[str, ...], str], ...] = ()
KNOWN_SUPPLEMENT_RULES: tuple[tuple[str, tuple[str, ...], str], ...] = ()


def _load_local_reconciliation_rules(
    db_path: Path | None,
) -> tuple[
    list[tuple[str, tuple[str, ...], str]],
    list[tuple[str, tuple[str, ...], str]],
]:
    """Load optional user-defined supersession/supplement rules from gitignored `local_reconciliation_rules.json`."""
    sup_rules: list[tuple[str, tuple[str, ...], str]] = list(KNOWN_SUPERSESSION_RULES)
    supp_rules: list[tuple[str, tuple[str, ...], str]] = list(KNOWN_SUPPLEMENT_RULES)
    if db_path is None:
        return sup_rules, supp_rules
    rules_path = db_path.parent / "local_reconciliation_rules.json"
    if not rules_path.exists() or not rules_path.is_file():
        return sup_rules, supp_rules
    try:
        raw = json.loads(rules_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            for item in raw.get("supersessions", []):
                if isinstance(item, dict) and item.get("newer_id") and item.get("older_ids"):
                    sup_rules.append(
                        (
                            str(item["newer_id"]),
                            tuple(str(x) for x in item["older_ids"]),
                            str(item.get("reason", "Local owner-defined supersession rule")),
                        )
                    )
            for item in raw.get("supplements", []):
                if isinstance(item, dict) and item.get("supplement_id") and item.get("base_ids"):
                    supp_rules.append(
                        (
                            str(item["supplement_id"]),
                            tuple(str(x) for x in item["base_ids"]),
                            str(item.get("reason", "Local owner-defined supplement link")),
                        )
                    )
    except Exception:
        return sup_rules, supp_rules
    return sup_rules, supp_rules


def _normalize_for_dedup(text: str) -> str:
    collapsed = re.sub(r"\s+", " ", text.lower()).strip()
    return collapsed


def _token_set(text: str) -> set[str]:
    tokens = set(re.findall(r"[a-z0-9]{3,}", text.lower()))
    stopwords = {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "are",
        "was",
        "not",
        "have",
        "has",
        "been",
        "were",
        "will",
        "into",
        "over",
        "also",
        "more",
        "than",
        "when",
        "where",
        "which",
        "about",
        "user",
        "context",
        "record",
        "status",
    }
    return tokens - stopwords


MONTH_MAP: dict[str, str] = {
    "jan": "01",
    "january": "01",
    "feb": "02",
    "february": "02",
    "mar": "03",
    "march": "03",
    "apr": "04",
    "april": "04",
    "may": "05",
    "jun": "06",
    "june": "06",
    "jul": "07",
    "july": "07",
    "aug": "08",
    "august": "08",
    "sep": "09",
    "sept": "09",
    "september": "09",
    "oct": "10",
    "october": "10",
    "nov": "11",
    "november": "11",
    "dec": "12",
    "december": "12",
}
ISO_DATE_RE = re.compile(r"\b((?:19|20)\d{2})(?:-(0[1-9]|1[0-2])(?:-(0[1-9]|[12]\d|3[01]))?)?\b")
NAMED_DATE_RE = re.compile(
    r"(?i)\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|"
    r"aug(?:ust)?|sep(?:t|tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"\s+(\d{1,2})(?:st|nd|rd|th)?(?:,\s*|\s+)((?:19|20)\d{2})\b"
)


def _parse_sortable_date(value: str | None) -> str:
    """Extract latest valid 19xx/20xx ISO or named-month date (`YYYY-MM-DD`) without false-matching ports/IDs."""
    if not value:
        return ""
    candidates: list[str] = []
    for m in ISO_DATE_RE.finditer(value):
        y, mo, d = m.group(1), m.group(2), m.group(3)
        if mo and d:
            candidates.append(f"{y}-{mo}-{d}")
        elif mo:
            candidates.append(f"{y}-{mo}-00")
        else:
            candidates.append(f"{y}-00-00")
    for m in NAMED_DATE_RE.finditer(value):
        mo_num = MONTH_MAP[m.group(1).lower()]
        day_num = f"{int(m.group(2)):02d}"
        year_num = m.group(3)
        candidates.append(f"{year_num}-{mo_num}-{day_num}")
    return max(candidates) if candidates else ""


def _record_authority_tuple(rec: dict[str, Any]) -> tuple[int, str, str, str]:
    ev = EvidenceClass(str(rec.get("evidence_class", EvidenceClass.UNKNOWN.value)))
    rank = EVIDENCE_RANK.get(ev, 0)
    confirmed = _parse_sortable_date(rec.get("last_confirmed_date"))
    observed = _parse_sortable_date(rec.get("observed_date"))
    effective = _parse_sortable_date(rec.get("effective_date"))
    return (rank, confirmed, observed, effective)


def reconcile_registry(registry: KnowledgeRegistry) -> dict[str, Any]:
    """Run deterministic cross-source reconciliation across the canonical registry.

    - Applies verified cross-source supersession rules (without deleting historical records).
    - Detects exact duplicate record bodies and marks lower-authority copies as SUPERSEDED.
    - Detects high-overlap semantic duplicate candidates and flags them for review.
    - Surfaces contradictory claims between active records with identical canonical subjects.
    - Ensures older/weaker evidence never silently supersedes newer confirmed information (Invariant 11).
    """
    records = registry.list_records()
    by_id = {str(r["logical_id"]): r for r in records}

    superseded_applied: list[dict[str, str]] = []
    supplements_linked: list[dict[str, str]] = []
    exact_duplicates: list[dict[str, str]] = []
    semantic_overlaps: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []

    sup_rules, supp_rules = _load_local_reconciliation_rules(getattr(registry.db, "db_path", None))

    # 1. Explicit owner-defined cross-source supersession rules (if configured locally)
    for newer_id, older_ids, reason in sup_rules:
        if newer_id not in by_id:
            continue
        newer = by_id[newer_id]
        if str(newer["status"]) == RecordStatus.SUPERSEDED.value:
            continue
        for old_id in older_ids:
            if old_id not in by_id:
                continue
            older = by_id[old_id]
            # Invariant 11 check: verify older record is not strictly newer & higher-authority
            if _record_authority_tuple(older) > _record_authority_tuple(newer) and (
                _parse_sortable_date(older.get("last_confirmed_date"))
                > _parse_sortable_date(newer.get("last_confirmed_date"))
            ):
                contradictions.append(
                    {
                        "record_a": newer_id,
                        "record_b": old_id,
                        "reason": "Potential reverse temporal conflict; manual review required",
                    }
                )
                registry.record_issue(
                    issue_id=f"conflict_{newer_id}_{old_id}",
                    issue_type="TEMPORAL_CONTRADICTION",
                    severity="HIGH",
                    logical_id=newer_id,
                    related_logical_id=old_id,
                    summary=f"Refused automatic supersession of {old_id} by {newer_id}: older record has newer confirmation.",
                )
                continue

            if (
                str(older["status"]) != RecordStatus.SUPERSEDED.value
                or older["destination_eligible"]
            ):
                registry.mark_superseded(old_id, newer_id, reason=reason)
                superseded_applied.append({"superseded": old_id, "by": newer_id, "reason": reason})

    # 2. Cross-reference supplement links (if configured locally)
    for supp_id, base_ids, reason in supp_rules:
        if supp_id not in by_id:
            continue
        for base_id in base_ids:
            if base_id in by_id:
                registry.add_relationship(supp_id, base_id, RelationType.SUPPLEMENTS, note=reason)
                supplements_linked.append({"supplement": supp_id, "base": base_id})

    # Reload active eligible records for duplicate & contradiction scanning
    active_records = [
        r
        for r in registry.list_records()
        if str(r["status"]) not in (RecordStatus.SUPERSEDED.value, RecordStatus.ARCHIVED.value)
    ]

    # 3. Exact body duplicate detection
    by_body_hash: dict[str, list[dict[str, Any]]] = {}
    for rec in active_records:
        h = sha256_text(_normalize_for_dedup(str(rec["body"])))
        by_body_hash.setdefault(h, []).append(rec)

    for _h, group in by_body_hash.items():
        if len(group) < 2:
            continue
        # Prefer destination_eligible=True, then highest authority/date, so an ineligible stub never supersedes a valid record
        group.sort(
            key=lambda r: (
                1 if r.get("destination_eligible") else 0,
                _record_authority_tuple(r),
                str(r["logical_id"]),
            ),
            reverse=True,
        )
        winner = group[0]
        for dup in group[1:]:
            registry.mark_superseded(
                str(dup["logical_id"]),
                str(winner["logical_id"]),
                reason="Exact normalized body duplicate",
            )
            exact_duplicates.append(
                {"duplicate": str(dup["logical_id"]), "kept": str(winner["logical_id"])}
            )
            registry.record_issue(
                issue_id=f"dup_exact_{dup['logical_id']}_{winner['logical_id']}",
                issue_type="EXACT_DUPLICATE",
                severity="INFO",
                logical_id=str(dup["logical_id"]),
                related_logical_id=str(winner["logical_id"]),
                summary=f"Exact duplicate {dup['logical_id']} superseded by {winner['logical_id']}",
            )

    # 4. Same canonical subject contradiction detection (for non-superseded active records)
    refreshed_active = [
        r
        for r in registry.list_records()
        if str(r["status"]) not in (RecordStatus.SUPERSEDED.value, RecordStatus.ARCHIVED.value)
        and r["destination_eligible"]
    ]
    by_subject: dict[str, list[dict[str, Any]]] = {}
    for rec in refreshed_active:
        subj = _normalize_for_dedup(str(rec["canonical_subject"]))
        if subj:
            by_subject.setdefault(subj, []).append(rec)

    for subj, group in by_subject.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda r: (_record_authority_tuple(r), str(r["logical_id"])), reverse=True)
        primary = group[0]
        for other in group[1:]:
            # If primary has strictly newer effective/observed/confirmed date AND equal/higher evidence rank,
            # supersede the older conflicting record rather than shipping both contradictory facts as current.
            p_auth = _record_authority_tuple(primary)
            o_auth = _record_authority_tuple(other)
            p_date = max(p_auth[1], p_auth[2], p_auth[3])
            o_date = max(o_auth[1], o_auth[2], o_auth[3])
            if p_date and o_date and p_date > o_date and p_auth[0] >= o_auth[0]:
                registry.mark_superseded(
                    str(other["logical_id"]),
                    str(primary["logical_id"]),
                    reason=f"Newer higher/equal-authority revision for subject '{subj}' ({p_date} > {o_date})",
                )
                superseded_applied.append(
                    {
                        "superseded": str(other["logical_id"]),
                        "by": str(primary["logical_id"]),
                        "reason": f"Temporal precedence ({p_date} > {o_date})",
                    }
                )
            else:
                registry.add_relationship(
                    str(primary["logical_id"]),
                    str(other["logical_id"]),
                    RelationType.CONTRADICTS,
                    note=f"Unresolved subject overlap: {subj}",
                )
                contradictions.append(
                    {
                        "subject": subj,
                        "record_a": str(primary["logical_id"]),
                        "record_b": str(other["logical_id"]),
                        "reason": "Two active records share canonical subject without unambiguous temporal/evidence precedence",
                    }
                )
                registry.record_issue(
                    issue_id=f"contradict_{primary['logical_id']}_{other['logical_id']}",
                    issue_type="CONTRADICTION",
                    severity="HIGH",
                    logical_id=str(primary["logical_id"]),
                    related_logical_id=str(other["logical_id"]),
                    summary=f"Contradictory/overlapping active records for subject '{subj}': {primary['logical_id']} vs {other['logical_id']}",
                )

    # 5. Semantic token overlap check using inverted-index pruning (near-O(N) on large registries)
    final_active = [
        r
        for r in registry.list_records()
        if str(r["status"]) not in (RecordStatus.SUPERSEDED.value, RecordStatus.ARCHIVED.value)
        and r["destination_eligible"]
    ]
    token_cache = {
        str(r["logical_id"]): _token_set(f"{r['title']} {r['body']}") for r in final_active
    }
    inverted: dict[str, list[int]] = {}
    max_df = max(25, len(final_active) // 4)
    for idx, rec in enumerate(final_active):
        toks = token_cache[str(rec["logical_id"])]
        if len(toks) < 10:
            continue
        for tok in toks:
            inverted.setdefault(tok, []).append(idx)

    pair_shared: dict[tuple[int, int], int] = {}
    for posting in inverted.values():
        if len(posting) < 2 or len(posting) > max_df:
            continue
        for a_pos in range(len(posting)):
            i = posting[a_pos]
            for b_pos in range(a_pos + 1, len(posting)):
                j = posting[b_pos]
                key = (i, j)
                pair_shared[key] = pair_shared.get(key, 0) + 1

    for (i, j), shared_rare in pair_shared.items():
        if shared_rare < 3:
            continue
        id1 = str(final_active[i]["logical_id"])
        id2 = str(final_active[j]["logical_id"])
        t1 = token_cache[id1]
        t2 = token_cache[id2]
        inter = len(t1 & t2)
        union = len(t1 | t2)
        jaccard = inter / union if union else 0.0
        if jaccard >= 0.72:
            semantic_overlaps.append(
                {"record_a": id1, "record_b": id2, "jaccard": round(jaccard, 3)}
            )
            registry.record_issue(
                issue_id=f"overlap_{min(id1, id2)}_{max(id1, id2)}",
                issue_type="SEMANTIC_OVERLAP",
                severity="WARNING",
                logical_id=id1,
                related_logical_id=id2,
                summary=f"High semantic overlap ({jaccard:.2f}) between {id1} and {id2}; review for merge or supersession.",
                details={"jaccard": round(jaccard, 3)},
            )

    return {
        "superseded_applied": superseded_applied,
        "supplements_linked": supplements_linked,
        "exact_duplicates": exact_duplicates,
        "semantic_overlaps": semantic_overlaps,
        "contradictions": contradictions,
        "active_eligible_count": len(final_active),
    }
