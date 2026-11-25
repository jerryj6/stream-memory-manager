"""Semantic Consolidation, Overlap Detection, Hygiene Triage, and Clean Voice-Friendly Formatting.

Fixes the 'scattered & sparse fragments' problem by clustering overlapping records across
sources (ChatGPT, Claude, Gemini, local coding agents, GitHub), flagging redundant meta-fluff
and stale windows, and merging them into dense, self-contained 650-900 word Topic Dossiers.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from stream_memory_manager.compiler import count_words_dual
from stream_memory_manager.models import (
    EVIDENCE_RANK,
    ErrorClass,
    EvidenceClass,
    ExitCode,
    InclusionDecision,
    MemoryRecordInput,
    RecordStatus,
    StreamMemoryError,
)
from stream_memory_manager.registry import KnowledgeRegistry

STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "are",
        "was",
        "were",
        "have",
        "has",
        "had",
        "not",
        "but",
        "you",
        "your",
        "about",
        "into",
        "over",
        "also",
        "more",
        "than",
        "when",
        "what",
        "which",
        "their",
        "they",
        "them",
        "will",
        "would",
        "should",
        "could",
        "does",
        "did",
        "been",
        "being",
        "only",
        "just",
        "very",
        "some",
        "such",
        "each",
        "other",
        "user",
        "context",
        "memory",
        "notes",
        "note",
        "confirmed",
        "constraint",
        "openloop",
        "inferred",
        "active",
        "status",
        "observed",
        "category",
    }
)

TAG_PREFIX_RE = re.compile(
    r"^(?P<bullet>\s*[-*•]\s*)"
    r"\[(?:Confirmed|Constraint|OpenLoop|Inferred|Recent|Verified|Historical)\]\s*"
    r"(?:\(\d{4}(?:-\d{2}(?:-\d{2})?)?\)\s*)?",
    re.IGNORECASE,
)

META_BOILERPLATE_PHRASES: tuple[str, ...] = (
    "never treat an exploratory question",
    "do not promote exploratory questions",
    "do not treat an assistant-generated",
    "never fabricate precision",
    "distinguish confirmed facts",
    "preserve the distinction between",
    "do not convert every passing thought",
    "treat this context as dated evidence",
    "do not discard useful historical context",
    "merge by semantic identity",
    "keep this supplemental export subordinate",
)

STALE_WINDOW_RE = re.compile(
    r"(?i)\b(?:black friday|preorder|not yet shipped|expected delivery|november hackathon|holiday sale)\b"
)


def strip_robotic_tag_prefixes(text: str) -> str:
    """Convert `[Confirmed] (2026-11) ...` / `[Constraint] ...` lines into clean voice-friendly bullets."""
    out: list[str] = []
    for line in text.splitlines():
        m = TAG_PREFIX_RE.match(line)
        if m:
            rest = line[m.end() :].strip()
            out.append(f"{m.group('bullet')}{rest}" if rest else line)
        else:
            out.append(line)
    return "\n".join(out)


def _tokenize_weighted(title: str, body: str) -> Counter[str]:
    """Extract informative lowercase tokens with 3x title weight for TF-IDF similarity."""
    t_toks = [t for t in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", title.lower()) if t not in STOPWORDS]
    b_toks = [t for t in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", body.lower()) if t not in STOPWORDS]
    counts: Counter[str] = Counter(b_toks)
    for tok in t_toks:
        counts[tok] += 3
    return counts


def _cosine_tfidf(
    vec_a: dict[str, float], norm_a: float, vec_b: dict[str, float], norm_b: float
) -> float:
    if norm_a <= 0.0 or norm_b <= 0.0:
        return 0.0
    if len(vec_a) > len(vec_b):
        vec_a, vec_b = vec_b, vec_a
    dot = sum(val * vec_b.get(k, 0.0) for k, val in vec_a.items())
    return dot / (norm_a * norm_b)


def classify_record_hygiene(rec: dict[str, Any]) -> list[dict[str, str]]:
    """Flag sparse fragments, redundant meta-boilerplate, and dated/stale shopping windows."""
    flags: list[dict[str, str]] = []
    title = str(rec.get("title", ""))
    body = str(rec.get("body", ""))
    low = body.lower()
    _, cons_words = count_words_dual(title, body)

    if cons_words < 120:
        flags.append(
            {
                "kind": "SPARSE_FRAGMENT",
                "label": f"Short ({cons_words}w)",
                "detail": "Consider merging into a broader topic dossier so Stream retrieves full context in one hit.",
            }
        )
    elif cons_words > 880:
        flags.append(
            {
                "kind": "OVER_BUDGET",
                "label": f"Will split ({cons_words}w)",
                "detail": "Over 880 words — will split into multiple parts unless tightened.",
            }
        )

    meta_hits = sum(1 for phrase in META_BOILERPLATE_PHRASES if phrase in low)
    if meta_hits >= 3 and "operating instructions" not in title.lower():
        flags.append(
            {
                "kind": "META_BOILERPLATE",
                "label": "Mostly meta-rules",
                "detail": f"Contains {meta_hits} repeated AI meta-instructions; fold any unique rules into Operating Instructions or archive.",
            }
        )

    if STALE_WINDOW_RE.search(body):
        flags.append(
            {
                "kind": "DATED_WINDOW",
                "label": "Time-bound / possibly stale",
                "detail": "Mentions a dated shopping/event window; review whether still relevant.",
            }
        )

    return flags


def analyze_corpus(
    registry: KnowledgeRegistry,
    *,
    similarity_threshold: float = 0.24,
    max_suggestions: int = 30,
) -> dict[str, Any]:
    """Analyze active records to surface merge candidates, sparse fragments, and meta-fluff."""
    records = [
        r
        for r in registry.list_records()
        if str(r["status"]) not in (RecordStatus.SUPERSEDED.value, RecordStatus.ARCHIVED.value)
        and str(r["inclusion_decision"]) != InclusionDecision.EXCLUDED.value
    ]
    n_docs = len(records)
    if n_docs == 0:
        return {
            "active_count": 0,
            "avg_words": 0,
            "sparse_count": 0,
            "boilerplate_count": 0,
            "merge_suggestions": [],
            "record_hygiene": {},
        }

    # Build TF-IDF vectors across active records
    raw_counts: list[Counter[str]] = []
    df: Counter[str] = Counter()
    word_counts: dict[str, int] = {}
    hygiene_map: dict[str, list[dict[str, str]]] = {}

    for rec in records:
        lid = str(rec["logical_id"])
        title = str(rec["title"])
        body = str(rec["body"])
        _, cw = count_words_dual(title, body)
        word_counts[lid] = cw
        hygiene_map[lid] = classify_record_hygiene(rec)
        c = _tokenize_weighted(title, body)
        raw_counts.append(c)
        for tok in c:
            df[tok] += 1

    tfidf_vecs: list[tuple[dict[str, float], float]] = []
    for c in raw_counts:
        vec: dict[str, float] = {}
        for tok, freq in c.items():
            idf = math.log((n_docs + 1.0) / (df[tok] + 1.0)) + 1.0
            vec[tok] = (1.0 + math.log(freq)) * idf
        norm = math.sqrt(sum(v * v for v in vec.values()))
        tfidf_vecs.append((vec, norm))

    suggestions: list[dict[str, Any]] = []
    for i in range(n_docs):
        rec_a = records[i]
        lid_a = str(rec_a["logical_id"])
        vec_a, norm_a = tfidf_vecs[i]
        title_toks_a = {
            t
            for t in re.findall(r"[a-z0-9]{3,}", str(rec_a["title"]).lower())
            if t not in STOPWORDS
        }
        for j in range(i + 1, n_docs):
            rec_b = records[j]
            lid_b = str(rec_b["logical_id"])
            vec_b, norm_b = tfidf_vecs[j]
            sim = _cosine_tfidf(vec_a, norm_a, vec_b, norm_b)
            title_toks_b = {
                t
                for t in re.findall(r"[a-z0-9]{3,}", str(rec_b["title"]).lower())
                if t not in STOPWORDS
            }
            shared_title = sorted(title_toks_a & title_toks_b)
            boost = 0.08 * min(2, len(shared_title))
            same_cat = str(rec_a["category"]).upper() == str(rec_b["category"]).upper()
            effective_sim = sim + boost + (0.03 if same_cat else 0.0)
            if effective_sim < similarity_threshold:
                continue

            combined_words = word_counts[lid_a] + word_counts[lid_b]
            # Find top shared terms to explain why these two overlap
            shared_terms = sorted(
                ((min(vec_a[k], vec_b[k]), k) for k in (set(vec_a.keys()) & set(vec_b.keys()))),
                reverse=True,
            )[:5]
            suggestions.append(
                {
                    "record_a": lid_a,
                    "title_a": str(rec_a["title"]),
                    "words_a": word_counts[lid_a],
                    "record_b": lid_b,
                    "title_b": str(rec_b["title"]),
                    "words_b": word_counts[lid_b],
                    "similarity": round(min(1.0, effective_sim), 3),
                    "combined_words_estimate": combined_words,
                    "fits_single_log": combined_words <= 880,
                    "shared_terms": [k for _, k in shared_terms],
                    "suggested_category": str(rec_a["category"]),
                }
            )

    suggestions.sort(key=lambda s: (-s["similarity"], s["combined_words_estimate"]))
    total_words = sum(word_counts.values())
    sparse_count = sum(
        1 for fl in hygiene_map.values() if any(f["kind"] == "SPARSE_FRAGMENT" for f in fl)
    )
    boilerplate_count = sum(
        1 for fl in hygiene_map.values() if any(f["kind"] == "META_BOILERPLATE" for f in fl)
    )

    return {
        "active_count": n_docs,
        "total_words": total_words,
        "avg_words": round(total_words / max(1, n_docs)),
        "sparse_count": sparse_count,
        "boilerplate_count": boilerplate_count,
        "merge_suggestions": suggestions[:max_suggestions],
        "record_hygiene": hygiene_map,
    }


def _dedupe_merged_lines(bodies: list[str]) -> str:
    """Combine multiple record bodies while removing exact/near-duplicate bullet lines."""
    seen_norm: set[str] = set()
    blocks: list[str] = []
    for raw in bodies:
        cleaned = strip_robotic_tag_prefixes(raw).strip()
        kept_lines: list[str] = []
        for ln in cleaned.splitlines():
            s = ln.strip()
            if not s:
                if kept_lines and kept_lines[-1] != "":
                    kept_lines.append("")
                continue
            norm = re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()
            if len(norm) >= 24 and norm in seen_norm:
                continue
            if len(norm) >= 24:
                seen_norm.add(norm)
            kept_lines.append(ln.rstrip())
        chunk = "\n".join(kept_lines).strip()
        if chunk:
            blocks.append(chunk)
    return "\n\n".join(blocks).strip()


def merge_records(
    registry: KnowledgeRegistry,
    source_ids: list[str],
    *,
    target_title: str,
    target_category: str | None = None,
    merged_body: str | None = None,
    approve: bool = True,
) -> dict[str, Any]:
    """Consolidate 2+ overlapping records into the primary canonical Topic Dossier.

    The first record in `source_ids` becomes the updated canonical dossier (creating a new
    revision); all remaining source records are marked `SUPERSEDED` with provenance links
    so nothing is silently lost and zero overlapping fragments remain active.
    """
    unique_ids = list(dict.fromkeys(s.strip() for s in source_ids if s.strip()))
    if len(unique_ids) < 2:
        raise StreamMemoryError(
            "Select at least 2 records to merge into a consolidated Topic Dossier.",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    recs: list[dict[str, Any]] = []
    for lid in unique_ids:
        rec = registry.get_record(lid)
        if rec is None:
            raise StreamMemoryError(
                f"Record not found for merge: {lid!r}",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        recs.append(rec)

    primary = recs[0]
    absorbed = recs[1:]
    primary_id = str(primary["logical_id"])

    # Compute union of provenance, aliases, highest evidence rank, newest confirmation date
    all_refs: list[str] = []
    all_hashes: list[str] = []
    all_aliases: list[str] = []
    best_ev = EvidenceClass(str(primary.get("evidence_class", EvidenceClass.USER_CONFIRMED.value)))
    newest_confirmed = str(primary.get("last_confirmed_date") or "")
    newest_observed = str(primary.get("observed_date") or "")

    for r in recs:
        for ref in r.get("source_refs") or []:
            if ref not in all_refs:
                all_refs.append(str(ref))
        for h in r.get("source_hashes") or []:
            if h not in all_hashes:
                all_hashes.append(str(h))
        for al in r.get("search_aliases") or []:
            if al not in all_aliases:
                all_aliases.append(str(al))
        ev = EvidenceClass(str(r.get("evidence_class", EvidenceClass.UNKNOWN.value)))
        if EVIDENCE_RANK.get(ev, 0) > EVIDENCE_RANK.get(best_ev, 0):
            best_ev = ev
        lc = str(r.get("last_confirmed_date") or "")
        if lc > newest_confirmed:
            newest_confirmed = lc
        ob = str(r.get("observed_date") or "")
        if ob > newest_observed:
            newest_observed = ob

    final_body = (
        merged_body.strip()
        if merged_body and merged_body.strip()
        else _dedupe_merged_lines([str(r["body"]) for r in recs])
    )
    final_cat = (target_category or str(primary["category"])).strip().upper()
    final_title = target_title.strip() or str(primary["title"])

    # Update primary record as a new revision
    registry.upsert_record(
        MemoryRecordInput(
            logical_id=primary_id,
            title=final_title,
            category=final_cat,
            logical_group=str(primary.get("logical_group") or f"Consolidated ({final_cat})"),
            canonical_subject=final_title,
            body=final_body,
            status=RecordStatus.ACTIVE,
            evidence_class=best_ev,
            effective_date=primary.get("effective_date")
            or newest_confirmed
            or newest_observed
            or None,
            observed_date=newest_observed or None,
            last_confirmed_date=newest_confirmed or None,
            source_refs=all_refs,
            source_hashes=all_hashes,
            search_aliases=all_aliases[:10],
            inclusion_decision=InclusionDecision.APPROVED
            if approve
            else InclusionDecision.PENDING_REVIEW,
            destination_eligible=True,
        )
    )

    absorbed_ids: list[str] = []
    for old_r in absorbed:
        old_id = str(old_r["logical_id"])
        registry.mark_superseded(
            old_id,
            primary_id,
            reason=f"Consolidated into unified Topic Dossier '{final_title}'",
        )
        absorbed_ids.append(old_id)

    ws, cons = count_words_dual(final_title, final_body)
    return {
        "primary_id": primary_id,
        "title": final_title,
        "category": final_cat,
        "absorbed_ids": absorbed_ids,
        "word_count": ws,
        "conservative_word_count": cons,
        "fits_single_log": cons <= 900,
    }


def build_agent_consolidation_pack(
    registry: KnowledgeRegistry,
    *,
    similarity_threshold: float = 0.24,
) -> dict[str, Any]:
    """Export a compact, agent-native handoff & overlap-cluster pack for the driving coding agent.

    Instead of calling external BYOK/Ollama APIs, the driving coding agent (Antigravity, Claude Code,
    Codex, Cursor, OpenCode) uses its own full reasoning directly on this pack and writes back clean,
    lossless 600-880 word Topic Dossiers via `stream-memory apply-dossiers`.
    """
    analysis = analyze_corpus(
        registry, similarity_threshold=similarity_threshold, max_suggestions=200
    )
    active = [
        r
        for r in registry.list_records()
        if str(r["status"]) not in (RecordStatus.SUPERSEDED.value, RecordStatus.ARCHIVED.value)
        and str(r["inclusion_decision"]) != InclusionDecision.EXCLUDED.value
    ]
    rec_by_id = {str(r["logical_id"]): r for r in active}
    hygiene = analysis["record_hygiene"]

    # Group pairwise overlaps into connected-component clusters for clean agent batch synthesis
    adj: dict[str, set[str]] = {lid: set() for lid in rec_by_id}
    for s in analysis["merge_suggestions"]:
        a = str(s["record_a"])
        b = str(s["record_b"])
        if a in adj and b in adj:
            adj[a].add(b)
            adj[b].add(a)

    visited: set[str] = set()
    clusters: list[dict[str, Any]] = []
    for lid in rec_by_id:
        if lid in visited or not adj[lid]:
            continue
        comp: list[str] = []
        stack = [lid]
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            comp.append(cur)
            for nb in sorted(adj[cur]):
                if nb not in visited:
                    stack.append(nb)
        comp.sort()
        total_w = sum(
            count_words_dual(str(rec_by_id[c]["title"]), str(rec_by_id[c]["body"]))[1] for c in comp
        )
        clusters.append(
            {
                "cluster_id": f"cluster_{len(clusters) + 1:02d}",
                "record_ids": comp,
                "titles": [str(rec_by_id[c]["title"]) for c in comp],
                "categories": sorted({str(rec_by_id[c]["category"]) for c in comp}),
                "raw_combined_words": total_w,
                "needs_dedupe_tightening": total_w > 880,
            }
        )

    records_payload = []
    for r in active:
        lid = str(r["logical_id"])
        _, cw = count_words_dual(str(r["title"]), str(r["body"]))
        records_payload.append(
            {
                "logical_id": lid,
                "title": str(r["title"]),
                "category": str(r["category"]),
                "word_count": cw,
                "hygiene_flags": hygiene.get(lid, []),
                "body": str(r["body"]),
            }
        )

    return {
        "schema": "STREAM_AGENT_CONSOLIDATION_PACK v1",
        "stats": {
            "active_count": analysis["active_count"],
            "total_words": analysis.get("total_words", 0),
            "avg_words": analysis["avg_words"],
            "sparse_count": analysis["sparse_count"],
            "boilerplate_count": analysis["boilerplate_count"],
            "overlap_cluster_count": len(clusters),
        },
        "target_guidelines": {
            "target_dossier_count": "12-25 dense, self-contained Topic Dossiers",
            "max_conservative_words_per_dossier": 880,
            "voice_style": (
                "Natural, direct prose and clean bullets. Strip robotic [Confirmed]/[Constraint] "
                "prefixes and repeated AI meta-rules. Preserve 100% of concrete facts, exact model "
                "numbers, versions, dates, negative results, NDA boundaries, and caveats."
            ),
        },
        "overlap_clusters": clusters,
        "records": records_payload,
        "apply_schema_example": {
            "dossiers": [
                {
                    "source_ids": ["id_primary", "id_overlap_1"],
                    "title": "Unified Topic Dossier Title",
                    "category": "ENGINEERING",
                    "body": "Clean, lossless consolidated prose <= 880 words...",
                }
            ],
            "retire_ids": [
                {
                    "logical_id": "id_redundant_meta",
                    "superseded_by": "id_primary",
                    "reason": "All unique rules folded into canonical Operating Instructions",
                }
            ],
        },
    }


def apply_agent_dossiers(
    registry: KnowledgeRegistry,
    payload: dict[str, Any],
    *,
    approve: bool = True,
) -> dict[str, Any]:
    """Atomically apply a driving coding agent's synthesized Topic Dossiers & retirements."""
    dossiers = payload.get("dossiers")
    retire_ids = payload.get("retire_ids") or []
    if not isinstance(dossiers, list) or (not dossiers and not retire_ids):
        raise StreamMemoryError(
            "Consolidation payload must include a non-empty `dossiers` list (or `retire_ids`).",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    before_active = [
        r
        for r in registry.list_records()
        if str(r["status"]) not in (RecordStatus.SUPERSEDED.value, RecordStatus.ARCHIVED.value)
        and str(r["inclusion_decision"]) != InclusionDecision.EXCLUDED.value
    ]
    before_count = len(before_active)

    applied: list[dict[str, Any]] = []
    oversized: list[dict[str, Any]] = []
    touched_ids: set[str] = set()

    for idx, item in enumerate(dossiers, start=1):
        if not isinstance(item, dict):
            raise StreamMemoryError(
                f"Dossier entry #{idx} must be a JSON object.",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        src_ids = [str(s).strip() for s in (item.get("source_ids") or []) if str(s).strip()]
        title = str(item.get("title") or "").strip()
        category = str(item.get("category") or "").strip().upper() or None
        raw_body = str(item.get("body") or "").strip()
        if not src_ids or not title or not raw_body:
            raise StreamMemoryError(
                f"Dossier entry #{idx} requires non-empty `source_ids`, `title`, and `body`.",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        clean_body = strip_robotic_tag_prefixes(raw_body).strip()
        touched_ids.update(src_ids)

        if len(src_ids) >= 2:
            mres = merge_records(
                registry,
                src_ids,
                target_title=title,
                target_category=category,
                merged_body=clean_body,
                approve=approve,
            )
            entry_res = mres
        else:
            primary_id = src_ids[0]
            rec = registry.get_record(primary_id)
            if rec is None:
                raise StreamMemoryError(
                    f"Record not found in dossier #{idx}: {primary_id!r}",
                    error_class=ErrorClass.VALIDATION_PERMANENT,
                    exit_code=ExitCode.VALIDATION_ERROR,
                )
            final_cat = category or str(rec["category"]).upper()
            registry.upsert_record(
                MemoryRecordInput(
                    logical_id=primary_id,
                    title=title,
                    category=final_cat,
                    logical_group=str(rec.get("logical_group") or f"Consolidated ({final_cat})"),
                    canonical_subject=title,
                    body=clean_body,
                    status=RecordStatus.ACTIVE,
                    evidence_class=EvidenceClass(
                        str(rec.get("evidence_class") or EvidenceClass.USER_CONFIRMED.value)
                    ),
                    effective_date=rec.get("effective_date"),
                    observed_date=rec.get("observed_date"),
                    last_confirmed_date=rec.get("last_confirmed_date"),
                    source_refs=list(rec.get("source_refs") or []),
                    source_hashes=list(rec.get("source_hashes") or []),
                    search_aliases=list(rec.get("search_aliases") or []),
                    inclusion_decision=(
                        InclusionDecision.APPROVED if approve else InclusionDecision.PENDING_REVIEW
                    ),
                    destination_eligible=True,
                )
            )
            ws, cons = count_words_dual(title, clean_body)
            entry_res = {
                "primary_id": primary_id,
                "title": title,
                "category": final_cat,
                "absorbed_ids": [],
                "word_count": ws,
                "conservative_word_count": cons,
                "fits_single_log": cons <= 900,
            }

        applied.append(entry_res)
        if not entry_res["fits_single_log"]:
            oversized.append(
                {
                    "primary_id": entry_res["primary_id"],
                    "title": entry_res["title"],
                    "conservative_word_count": entry_res["conservative_word_count"],
                }
            )

    retired: list[str] = []
    for r_item in retire_ids:
        if not isinstance(r_item, dict):
            continue
        old_id = str(r_item.get("logical_id") or "").strip()
        sup_by = str(r_item.get("superseded_by") or "").strip()
        reason = str(r_item.get("reason") or "Retired during agent consolidation").strip()
        if not old_id or not sup_by:
            continue
        if registry.get_record(old_id) is None or registry.get_record(sup_by) is None:
            raise StreamMemoryError(
                f"Invalid retirement reference: logical_id={old_id!r}, superseded_by={sup_by!r}",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        registry.mark_superseded(old_id, sup_by, reason=reason)
        retired.append(old_id)
        touched_ids.add(old_id)

    after_active = [
        r
        for r in registry.list_records()
        if str(r["status"]) not in (RecordStatus.SUPERSEDED.value, RecordStatus.ARCHIVED.value)
        and str(r["inclusion_decision"]) != InclusionDecision.EXCLUDED.value
    ]
    unmodified = [
        str(r["logical_id"]) for r in after_active if str(r["logical_id"]) not in touched_ids
    ]

    return {
        "before_active_count": before_count,
        "after_active_count": len(after_active),
        "dossiers_applied": len(applied),
        "retired_count": len(retired),
        "oversized_dossiers": oversized,
        "unmodified_active_ids": unmodified,
        "dossiers": applied,
    }
