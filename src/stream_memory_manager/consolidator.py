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

import httpx2

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
from stream_memory_manager.security import redact_secrets

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


async def auto_consolidate_with_llm(
    records: list[dict[str, Any]],
    *,
    target_title: str,
    base_url: str,
    model: str,
    api_key: str | None = None,
    max_words: int = 820,
) -> str:
    """Optional opt-in BYOK / local Ollama consolidation of overlapping records into one dense dossier.

    Compatible with any OpenAI-format `/v1/chat/completions` endpoint (OpenAI, OpenRouter,
    local Ollama `http://localhost:11434/v1`, LM Studio, Apple MLX server).
    """
    clean_base = base_url.rstrip("/")
    endpoint = (
        clean_base if clean_base.endswith("/chat/completions") else f"{clean_base}/chat/completions"
    )
    source_blocks = "\n\n---\n\n".join(
        f"### {r.get('title', 'Untitled')}\n{r.get('body', '')}" for r in records
    )
    system_prompt = (
        "You consolidate overlapping personal & technical AI memory notes into ONE dense, "
        "self-contained, naturally written dossier for Sandbar Stream voice & text retrieval. "
        f"Target <= {max_words} words. Keep EVERY concrete fact, number, model name, project status, "
        "preference, negative result, and caveat. Eliminate duplicate sentences, generic AI boilerplate, "
        "and robotic [Confirmed]/[Constraint] tag prefixes. Separate built/verified work from proposed "
        "designs. Never invent facts not present in the sources. Output ONLY the clean consolidated note body."
    )
    user_prompt = (
        f"Target Dossier Title: {target_title}\n\nSource Notes to Consolidate:\n\n{source_blocks}"
    )

    headers = {"Content-Type": "application/json"}
    if api_key and api_key.strip():
        headers["Authorization"] = f"Bearer {api_key.strip()}"

    payload = {
        "model": model.strip(),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }

    async with httpx2.AsyncClient(timeout=90.0) as client:
        resp = await client.post(endpoint, headers=headers, json=payload)
        if resp.status_code >= 400:
            raise StreamMemoryError(
                f"LLM consolidation endpoint returned HTTP {resp.status_code}: {redact_secrets(resp.text[:300])}",
                error_class=ErrorClass.READ_TRANSIENT,
                exit_code=ExitCode.TEMPORARY_FAILURE,
            )
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            raise StreamMemoryError(
                "LLM consolidation returned no choices.",
                error_class=ErrorClass.READ_TRANSIENT,
                exit_code=ExitCode.TEMPORARY_FAILURE,
            )
        msg = choices[0].get("message") or {}
        content = str(msg.get("content") or "").strip()
        if not content:
            raise StreamMemoryError(
                "LLM consolidation returned empty content.",
                error_class=ErrorClass.READ_TRANSIENT,
                exit_code=ExitCode.TEMPORARY_FAILURE,
            )
        return redact_secrets(content)
