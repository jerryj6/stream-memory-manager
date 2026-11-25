"""Deterministic Semantic Memory Compiler for Sandbar Stream Logs, Folder Instructions, and Briefing."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from stream_memory_manager.models import (
    CompiledArtifact,
    ErrorClass,
    ExitCode,
    StreamMemoryError,
    utc_now_iso,
)
from stream_memory_manager.privacy import assert_payload_safe, assert_record_exportable
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import canonical_json_hash

COMPILER_VERSION = "1.0.0"
DEFAULT_MAX_WORDS = 900
SANDBAR_HARD_WORD_LIMIT = 1000
SANDBAR_FOLDER_NAME_LIMIT = 30
SANDBAR_FOLDER_INSTRUCTION_LIMIT = 140
DEFAULT_BRIEFING_MAX_WORDS = 220

DEFAULT_FOLDER_INSTRUCTION = (
    "Dated personal & technical memory logs. Apply naturally; prefer newer corrections; "
    "separate built vs proposed; retrieve full logs."
)

# Deterministic import ordering priorities (Section 23)
CATEGORY_ORDER: dict[str, int] = {
    "CORE": 100,
    "PREFERENCES": 200,
    "ACADEMICS": 300,
    "CAREER": 320,
    "PERSONAL": 350,
    "ENGINEERING": 400,
    "CIVIC": 420,
    "RESEARCH": 440,
    "SOFTWARE": 460,
    "HARDWARE": 480,
    "INFRASTRUCTURE": 500,
    "PROJECTS": 520,
    "CURRENT": 600,
    "WORKFLOWS": 650,
    "HISTORY": 700,
    "GENERAL": 800,
}

# Zero-width & exotic Unicode whitespace characters to normalize when counting words
EXOTIC_SPACE_RE = re.compile(
    r"[\u00a0\u1680\u2000-\u200d\u2028\u2029\u202f\u205f\u2060\u3000\ufeff]"
)
PUNCT_WORD_SPLIT_RE = re.compile(r"[\s/\u2014\u2013|,;]+")


def normalize_remote_text(text: str) -> str:
    """Documented conservative text normalization policy for remote persistence verification.

    Permits only:
    - CRLF / CR -> LF line endings
    - Removal of trailing whitespace per line and leading/trailing outer blank lines.
    Does NOT hide substantive text edits, missing lines, or punctuation rewrites.
    """
    unified = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in unified.split("\n")]
    return "\n".join(lines).strip()


def count_words_dual(title: str, body: str) -> tuple[int, int]:
    """Compute (whitespace_word_count, conservative_word_count) over title + body combined.

    Conservative count accounts for:
    - Unicode NFKC normalization and exotic/zero-width whitespace
    - Servers that tokenize across slashes, em-dashes, pipes, or punctuation
    - Extremely long unbroken tokens (>60 chars) penalized proportionally so pathological
      inputs cannot slip past server-side tokenizers/limits.
    """
    combined = f"{title}\n{body}"
    nfkc = unicodedata.normalize("NFKC", combined)
    cleaned = EXOTIC_SPACE_RE.sub(" ", nfkc)

    ws_tokens = [tok for tok in cleaned.split() if tok]
    ws_count = len(ws_tokens)

    # Conservative tokenization: split on whitespace + slash/dash/pipe + penalize >60-char unbroken runs
    conservative_tokens = [t for t in PUNCT_WORD_SPLIT_RE.split(cleaned) if t]
    conservative_count = 0
    for tok in conservative_tokens:
        if len(tok) > 60:
            conservative_count += max(1, (len(tok) + 29) // 30)
        else:
            conservative_count += 1

    return ws_count, max(ws_count, conservative_count)


def validate_log_payload(
    title: str, body: str, *, max_words: int = DEFAULT_MAX_WORDS
) -> tuple[int, int]:
    """Strictly validate serialized Stream Log length before compilation or network write."""
    if max_words >= SANDBAR_HARD_WORD_LIMIT:
        raise StreamMemoryError(
            f"Configured max_words ({max_words}) must be strictly below Sandbar hard limit ({SANDBAR_HARD_WORD_LIMIT})",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    if not title.strip():
        raise StreamMemoryError(
            "Compiled Log title cannot be empty",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    if not body.strip():
        raise StreamMemoryError(
            f"Compiled Log body cannot be empty for title {title!r}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    ws_count, cons_count = count_words_dual(title, body)
    if cons_count > max_words:
        raise StreamMemoryError(
            f"Compiled Log {title!r} exceeds word ceiling: conservative={cons_count}, "
            f"whitespace={ws_count}, ceiling={max_words}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    return ws_count, cons_count


def format_stream_title(category: str, raw_title: str) -> str:
    """Produce a clean, recognizable `CATEGORY — Title` Stream title without noisy IDs."""
    cat = category.strip().upper()
    clean = re.sub(r"^(?:\d{2}-\d{2}|T\d{2}|P\d{2})\s*[—–-]\s*", "", raw_title.strip())
    if clean.upper().startswith(f"{cat} — ") or clean.upper().startswith(f"{cat} - "):
        return clean
    return f"{cat} — {clean}"


TAG_LINE_PREFIX_RE = re.compile(
    r"^(?P<bullet>\s*[-*•]\s*)"
    r"\[(?:Confirmed|Constraint|OpenLoop|Inferred|Recent|Verified|Historical)\]\s*"
    r"(?:\(\d{4}(?:-\d{2}(?:-\d{2})?)?\)\s*)?",
    re.IGNORECASE,
)


MD_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<text>.+?)\s*#*$")
MD_BOLD_RE = re.compile(r"\*\*(?P<inner>[^*\n]+?)\*\*")


def _clean_voice_prose(body: str) -> str:
    """Format clean, voice- and Stream-Web-friendly plain text (Stream renders raw Markdown literally).

    - Strips robotic `[Confirmed] (2026-11)` / `[Constraint]` tag prefixes.
    - Converts raw `## Heading` lines to clean plain-text headings and unwraps `**bold**` markers.
    - Leaves fenced code blocks untouched.
    """
    out: list[str] = []
    in_fence = False
    for line in body.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        m = TAG_LINE_PREFIX_RE.match(line)
        if m:
            rest = line[m.end() :].strip()
            line = f"{m.group('bullet')}{rest}" if rest else line
        hm = MD_HEADING_RE.match(line)
        if hm:
            heading = MD_BOLD_RE.sub(r"\g<inner>", hm.group("text").strip())
            out.append(heading if heading.endswith(":") else f"{heading}:")
            continue
        cleaned_line = MD_BOLD_RE.sub(r"\g<inner>", line)
        out.append(cleaned_line)
    return "\n".join(out)


def _format_record_body(rec: dict[str, Any]) -> str:
    """Render clean, voice-friendly, self-contained Stream Log prose without noisy admin headers."""
    lines: list[str] = []
    status = str(rec.get("status", "ACTIVE"))
    if status != "ACTIVE":
        lines.append(f"Status: {status}")
        lines.append("")

    lines.append(_clean_voice_prose(str(rec["body"]).strip()))

    aliases = rec.get("search_aliases") or []
    if aliases:
        clean_aliases = [str(a).strip() for a in aliases[:10] if str(a).strip()]
        if clean_aliases:
            lines.append("")
            lines.append(f"Related terms: {', '.join(clean_aliases)}")

    return normalize_remote_text("\n".join(lines))


def _split_semantic_blocks(body: str) -> list[str]:
    """Split markdown body into coherent semantic blocks (keeping fenced code blocks intact)."""
    blocks: list[str] = []
    current: list[str] = []
    in_fence = False

    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            current.append(line)
            continue
        if in_fence:
            current.append(line)
            continue
        if stripped.startswith("## ") and current:
            blocks.append("\n".join(current).strip())
            current = [line]
            continue
        if stripped == "" and current:
            blocks.append("\n".join(current).strip())
            current = []
            continue
        current.append(line)
    if current:
        blocks.append("\n".join(current).strip())
    return [b for b in blocks if b]


def _split_oversize_block(block: str, max_words: int) -> list[str]:
    """Split a single oversized block while preserving fenced code blocks and markdown bullets. Never truncates."""
    lines = block.splitlines()
    # Preserve fenced code blocks by splitting on line boundaries and re-closing/re-opening fences cleanly
    if (
        len(lines) >= 2
        and lines[0].strip().startswith("```")
        and lines[-1].strip().startswith("```")
    ):
        fence_open = lines[0].strip()
        inner_lines = lines[1:-1]
        parts: list[str] = []
        buf: list[str] = []
        for ln in inner_lines:
            cand = "\n".join([fence_open, *buf, ln, "```"])
            if count_words_dual("", cand)[1] <= max_words:
                buf.append(ln)
            else:
                if buf:
                    parts.append("\n".join([fence_open, *buf, "```"]))
                buf = [ln]
        if buf:
            parts.append("\n".join([fence_open, *buf, "```"]))
        return parts

    # Preserve bulleted / multi-line structured lists by splitting on line boundaries first
    if len(lines) > 1 and any(ln.lstrip().startswith(("- ", "* ", "### ")) for ln in lines):
        parts = []
        buf = []
        for ln in lines:
            cand = "\n".join([*buf, ln]).strip()
            if count_words_dual("", cand)[1] <= max_words:
                buf.append(ln)
            else:
                if buf:
                    parts.append("\n".join(buf).strip())
                    buf = []
                if count_words_dual("", ln)[1] <= max_words:
                    buf = [ln]
                else:
                    parts.extend(_split_single_prose_block(ln, max_words))
        if buf:
            parts.append("\n".join(buf).strip())
        return parts

    return _split_single_prose_block(block, max_words)


def _split_single_prose_block(block: str, max_words: int) -> list[str]:
    """Split a single prose paragraph by sentence boundaries, or word chunks if a sentence exceeds limit."""
    sentences = re.split(r"(?<=[.!?])\s+", block)
    parts: list[str] = []
    buf: list[str] = []
    for sent in sentences:
        candidate = " ".join([*buf, sent]).strip()
        _, cons = count_words_dual("", candidate)
        if cons <= max_words:
            buf.append(sent)
            continue
        if buf:
            parts.append(" ".join(buf).strip())
            buf = []
        _, sent_cons = count_words_dual("", sent)
        if sent_cons <= max_words:
            buf = [sent]
        else:
            tokens = sent.split()
            chunk: list[str] = []
            for tok in tokens:
                if len(tok) > 120:
                    if chunk:
                        parts.append(" ".join(chunk))
                        chunk = []
                    for i in range(0, len(tok), 60):
                        parts.append(tok[i : i + 60])
                    continue
                cand = " ".join([*chunk, tok])
                _, c_cons = count_words_dual("", cand)
                if c_cons <= max_words:
                    chunk.append(tok)
                else:
                    if chunk:
                        parts.append(" ".join(chunk))
                    chunk = [tok]
            if chunk:
                parts.append(" ".join(chunk))
    if buf:
        parts.append(" ".join(buf).strip())
    return parts


def semantic_split_log(
    title: str,
    body: str,
    *,
    max_words: int = DEFAULT_MAX_WORDS,
) -> list[tuple[str, str]]:
    """Split an oversized Log semantically with part suffixes and cross-references. Never truncates."""
    _, cons = count_words_dual(title, body)
    if cons <= max_words:
        return [(title, body)]

    # Reserve headroom for BOTH part_title AND nav_note (which repeats `title`!) -> 2 * title_words + 45
    title_words = count_words_dual(title + " (Part 99 of 99)", "")[1]
    body_budget = max(60, max_words - (2 * title_words) - 45)

    raw_blocks = _split_semantic_blocks(body)
    blocks: list[str] = []
    for blk in raw_blocks:
        _, b_cons = count_words_dual("", blk)
        if b_cons <= body_budget:
            blocks.append(blk)
        else:
            blocks.extend(_split_oversize_block(blk, body_budget))

    chunks: list[str] = []
    cur: list[str] = []
    for blk in blocks:
        cand = "\n\n".join([*cur, blk]).strip()
        _, c_cons = count_words_dual("", cand)
        if c_cons <= body_budget:
            cur.append(blk)
        else:
            if cur:
                chunks.append("\n\n".join(cur).strip())
            cur = [blk]
    if cur:
        chunks.append("\n\n".join(cur).strip())

    total = len(chunks)
    if total == 1:
        validate_log_payload(title, chunks[0], max_words=max_words)
        return [(title, chunks[0])]

    outputs: list[tuple[str, str]] = []
    for idx, chunk in enumerate(chunks, start=1):
        part_title = f"{title} (Part {idx} of {total})"
        nav_note = f"Series note: Part {idx} of {total} for '{title}'. " + (
            f"Continued in Part {idx + 1}." if idx < total else "Final part of series."
        )
        part_body = normalize_remote_text(f"{chunk}\n\n{nav_note}")
        validate_log_payload(part_title, part_body, max_words=max_words)
        outputs.append((part_title, part_body))
    return outputs


def _build_knowledge_index_logs(
    compiled_logs: list[CompiledArtifact],
    *,
    max_words: int,
) -> list[CompiledArtifact]:
    """Generate compact multi-resolution CORE Knowledge Index Log(s) pointing to compiled records."""
    by_cat: dict[str, list[str]] = {}
    for art in compiled_logs:
        by_cat.setdefault(art.category, []).append(art.title)

    lines = [
        "Unified navigation index for managed records in the Memory folder.",
        "Retrieve full domain Logs for authoritative details rather than relying only on summaries.",
        "",
    ]
    for cat in sorted(by_cat.keys(), key=lambda c: (CATEGORY_ORDER.get(c, 900), c)):
        lines.append(f"## {cat}")
        for title in by_cat[cat]:
            lines.append(f"- {title}")
        lines.append("")

    full_body = normalize_remote_text("\n".join(lines))
    parts = semantic_split_log("CORE — Knowledge Index", full_body, max_words=max_words)
    artifacts: list[CompiledArtifact] = []
    for idx, (ptitle, pbody) in enumerate(parts, start=1):
        ws, cons = validate_log_payload(ptitle, pbody, max_words=max_words)
        norm_hash = canonical_json_hash({"title": normalize_remote_text(ptitle), "body": pbody})
        payload_hash = canonical_json_hash({"title": ptitle, "body": pbody, "kind": "log"})
        artifacts.append(
            CompiledArtifact(
                artifact_key=f"core_knowledge_index:p{idx}",
                logical_id="core_knowledge_index",
                revision_number=1,
                artifact_kind="log",
                category="CORE",
                title=ptitle,
                body=pbody,
                part_index=idx,
                part_total=len(parts),
                word_count=ws,
                conservative_word_count=cons,
                char_count=len(ptitle) + len(pbody),
                payload_hash=payload_hash,
                normalized_payload_hash=norm_hash,
                compiler_version=COMPILER_VERSION,
                order_priority=690,  # Imported after subject logs per Section 23 ordering!
            )
        )
    return artifacts


def _build_briefing_artifact(
    compiled_logs: list[CompiledArtifact],
    approved_records: list[dict[str, Any]] | None = None,
) -> CompiledArtifact:
    """Build a dense, high-signal Stream Briefing ready for 1-click copy into Stream's Briefing field."""
    word_budget = DEFAULT_BRIEFING_MAX_WORDS - 12
    topic_logs = [a for a in compiled_logs if not a.artifact_key.startswith("core_knowledge_index")]

    # Always preserve the full actionable retrieval directive intact
    directive = (
        "Search and retrieve the relevant Memory note before asking me to repeat established context. "
        "Prefer newer corrections, separate built/verified work from proposals, and keep voice replies direct."
    )
    directive_words = len(directive.split())

    # Reserve ~100 words for complete sentences from the CORE briefing record
    intro_budget = min(105, max(45, (word_budget - directive_words) // 2 + 12))
    intro_text = ""
    if approved_records:
        # Prefer explicit personal Briefing / Profile / Background record over Operating Instructions
        briefing_rec = (
            next(
                (
                    r
                    for r in approved_records
                    if any(
                        kw in str(r.get("title", "")).lower()
                        for kw in ("briefing", "profile", "background", "about me")
                    )
                ),
                None,
            )
            or next(
                (
                    r
                    for r in approved_records
                    if str(r.get("category", "")).upper() == "CORE"
                    and "operating instruction" not in str(r.get("title", "")).lower()
                ),
                None,
            )
            or next(
                (r for r in approved_records if str(r.get("category", "")).upper() == "CORE"),
                None,
            )
        )
        if briefing_rec is not None:
            raw_b = _clean_voice_prose(str(briefing_rec.get("body", "")).strip())
            clean_lines = [
                re.sub(r"^\s*[-*•]\s+", "", ln.strip())
                for ln in raw_b.splitlines()
                if ln.strip() and not ln.strip().startswith("#") and not ln.strip().endswith(":")
            ]
            flat = " ".join(clean_lines)
            sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", flat) if s.strip()]
            chosen: list[str] = []
            used = 0
            for sent in sentences:
                sw = len(sent.split())
                if used + sw > intro_budget:
                    if not chosen:
                        chosen.append(" ".join(sent.split()[:intro_budget]).rstrip(".,;:") + ".")
                    break
                chosen.append(sent)
                used += sw
            intro_text = " ".join(chosen).strip()

    # Pack complete dossier titles cleanly into the remaining word budget (never chop mid-title!)
    intro_words = len(intro_text.split()) if intro_text else 0
    topics_budget = max(20, word_budget - directive_words - intro_words - 14)
    chosen_titles: list[str] = []
    used_t = 0
    remaining_cats: list[str] = []
    for a in topic_logs:
        short_title = a.title.split(" — ", 1)[1] if " — " in a.title else a.title
        tw = len(short_title.split())
        if used_t + tw <= topics_budget or not chosen_titles:
            chosen_titles.append(short_title)
            used_t += tw
        elif a.category not in remaining_cats:
            remaining_cats.append(a.category)

    omitted = len(topic_logs) - len(chosen_titles)
    tail = (
        f" (+{omitted} more across {', '.join(remaining_cats)})"
        if omitted > 0 and remaining_cats
        else (f" (+{omitted} more)" if omitted > 0 else "")
    )
    directory_line = (
        f"Memory folder ({len(topic_logs)} dossiers): {'; '.join(chosen_titles)}{tail}."
        if topic_logs
        else ""
    )

    parts = [p for p in (intro_text, directory_line, directive) if p]
    body = normalize_remote_text("\n\n".join(parts))

    ws, cons = validate_log_payload(
        "Stream Memory Briefing", body, max_words=DEFAULT_BRIEFING_MAX_WORDS + 40
    )
    return CompiledArtifact(
        artifact_key="meta_mcp_briefing",
        logical_id="meta_mcp_briefing",
        revision_number=1,
        artifact_kind="briefing",
        category="CORE",
        title="Stream Memory Briefing",
        body=body,
        part_index=1,
        part_total=1,
        word_count=ws,
        conservative_word_count=cons,
        char_count=len(body),
        payload_hash=canonical_json_hash({"kind": "briefing", "body": body}),
        normalized_payload_hash=canonical_json_hash({"body": body}),
        compiler_version=COMPILER_VERSION,
        order_priority=950,
    )


def _build_folder_instruction_artifact(instruction_text: str | None = None) -> CompiledArtifact:
    text = normalize_remote_text(instruction_text or DEFAULT_FOLDER_INSTRUCTION)
    if len(text) > SANDBAR_FOLDER_INSTRUCTION_LIMIT:
        raise StreamMemoryError(
            f"Folder instruction exceeds Sandbar 140-character limit ({len(text)} chars)",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    ws, cons = count_words_dual("", text)
    return CompiledArtifact(
        artifact_key="meta_folder_instruction",
        logical_id="meta_folder_instruction",
        revision_number=1,
        artifact_kind="folder_instruction",
        category="CORE",
        title="Memory Folder Instruction",
        body=text,
        part_index=1,
        part_total=1,
        word_count=ws,
        conservative_word_count=cons,
        char_count=len(text),
        payload_hash=canonical_json_hash({"kind": "folder_instruction", "body": text}),
        normalized_payload_hash=canonical_json_hash({"body": text}),
        compiler_version=COMPILER_VERSION,
        order_priority=900,
    )


def compile_memory(
    registry: KnowledgeRegistry,
    *,
    max_words: int = DEFAULT_MAX_WORDS,
    include_index: bool = True,
    include_briefing: bool = True,
    folder_instruction: str | None = None,
    allow_unresolved_contradictions: bool = False,
) -> dict[str, Any]:
    """Deterministically compile all approved, eligible canonical records into Stream-ready artifacts."""
    all_records = registry.list_records(only_destination_eligible=True)
    approved_records = [
        r
        for r in all_records
        if str(r["inclusion_decision"]) == "APPROVED"
        and str(r["status"]) not in ("SUPERSEDED", "DRAFT", "ARCHIVED")
    ]
    approved_ids = {str(r["logical_id"]) for r in approved_records}

    # Gate unresolved HIGH contradictions touching approved records (Audit R17)
    if not allow_unresolved_contradictions:
        open_contradictions = [
            iss
            for iss in registry.list_issues(status="OPEN")
            if iss["issue_type"] in ("CONTRADICTION", "TEMPORAL_CONTRADICTION")
            and (
                str(iss.get("logical_id") or "") in approved_ids
                or str(iss.get("related_logical_id") or "") in approved_ids
            )
        ]
        if open_contradictions:
            raise StreamMemoryError(
                f"Cannot compile: {len(open_contradictions)} unresolved contradiction(s) affect approved records. "
                "Resolve or supersede conflicting records first.",
                error_class=ErrorClass.CONFLICT_ERROR,
                exit_code=ExitCode.BLOCKED_CONFLICT,
                details={"issue_ids": [i["issue_id"] for i in open_contradictions]},
            )

    compiled_logs: list[CompiledArtifact] = []
    skipped_unapproved = len(all_records) - len(approved_records)

    def _sort_key(rec: dict[str, Any]) -> tuple[int, str]:
        cat = str(rec["category"]).upper()
        base = CATEGORY_ORDER.get(cat, 800)
        lid = str(rec["logical_id"])
        if "operating_instructions" in str(rec["title"]).lower() or lid in ("v2_00_04", "tech_t01"):
            base = 50
        elif "briefing" in str(rec["title"]).lower() or lid == "v2_01_01":
            base = 80
        return (base, lid)

    approved_records.sort(key=_sort_key)

    seen_titles: dict[str, str] = {}
    for rec in approved_records:
        assert_record_exportable(rec)
        lid = str(rec["logical_id"])
        rev = int(rec["current_revision"])
        cat = str(rec["category"]).upper()
        stream_title = format_stream_title(cat, str(rec["title"]))
        norm_stream_title = normalize_remote_text(stream_title)
        if norm_stream_title in seen_titles:
            raise StreamMemoryError(
                f"Duplicate compiled Stream title {stream_title!r} produced by records "
                f"{seen_titles[norm_stream_title]!r} and {lid!r}; disambiguate titles before compiling.",
                error_class=ErrorClass.CONFLICT_ERROR,
                exit_code=ExitCode.BLOCKED_CONFLICT,
            )
        seen_titles[norm_stream_title] = lid
        stream_body = _format_record_body(rec)
        parts = semantic_split_log(stream_title, stream_body, max_words=max_words)
        priority = _sort_key(rec)[0]

        for idx, (ptitle, pbody) in enumerate(parts, start=1):
            ws, cons = validate_log_payload(ptitle, pbody, max_words=max_words)
            assert_payload_safe(ptitle, pbody, label=f"{lid}:p{idx}")
            norm_title = normalize_remote_text(ptitle)
            norm_body = normalize_remote_text(pbody)
            norm_hash = canonical_json_hash({"title": norm_title, "body": norm_body})
            payload_hash = canonical_json_hash(
                {"title": ptitle, "body": pbody, "kind": "log", "logical_id": lid, "revision": rev}
            )
            compiled_logs.append(
                CompiledArtifact(
                    artifact_key=f"{lid}:p{idx}",
                    logical_id=lid,
                    revision_number=rev,
                    artifact_kind="log",
                    category=cat,
                    title=ptitle,
                    body=pbody,
                    part_index=idx,
                    part_total=len(parts),
                    word_count=ws,
                    conservative_word_count=cons,
                    char_count=len(ptitle) + len(pbody),
                    payload_hash=payload_hash,
                    normalized_payload_hash=norm_hash,
                    compiler_version=COMPILER_VERSION,
                    order_priority=priority,
                )
            )

    all_logs: list[CompiledArtifact] = list(compiled_logs)
    if include_index and compiled_logs:
        idx_logs = _build_knowledge_index_logs(compiled_logs, max_words=max_words)
        for idx_art in idx_logs:
            assert_payload_safe(idx_art.title, idx_art.body, label=idx_art.artifact_key)
        all_logs.extend(idx_logs)

    all_artifacts: list[CompiledArtifact] = list(all_logs)

    folder_instr_art = _build_folder_instruction_artifact(folder_instruction)
    assert_payload_safe(
        folder_instr_art.title, folder_instr_art.body, label=folder_instr_art.artifact_key
    )
    all_artifacts.append(folder_instr_art)

    if include_briefing and all_logs:
        brief_art = _build_briefing_artifact(all_logs, approved_records)
        assert_payload_safe(brief_art.title, brief_art.body, label=brief_art.artifact_key)
        all_artifacts.append(brief_art)

    all_artifacts.sort(key=lambda a: (a.order_priority, a.artifact_key))

    now = utc_now_iso()
    with registry.db.transaction() as conn:
        conn.execute("DELETE FROM compiled_artifacts;")
        for art in all_artifacts:
            conn.execute(
                """
                INSERT INTO compiled_artifacts (
                    artifact_key, logical_id, revision_number, artifact_kind, category,
                    title, body, part_index, part_total, word_count, conservative_word_count,
                    char_count, payload_hash, normalized_payload_hash, compiler_version,
                    order_priority, compiled_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    art.artifact_key,
                    art.logical_id,
                    art.revision_number,
                    art.artifact_kind,
                    art.category,
                    art.title,
                    art.body,
                    art.part_index,
                    art.part_total,
                    art.word_count,
                    art.conservative_word_count,
                    art.char_count,
                    art.payload_hash,
                    art.normalized_payload_hash,
                    art.compiler_version,
                    art.order_priority,
                    now,
                ),
            )

    logs_only = [a for a in all_artifacts if a.artifact_kind == "log"]
    cat_dist: dict[str, int] = {}
    for a in logs_only:
        cat_dist[a.category] = cat_dist.get(a.category, 0) + 1

    manifest_hash = canonical_json_hash(
        [
            {
                "key": a.artifact_key,
                "kind": a.artifact_kind,
                "payload_hash": a.payload_hash,
                "order": a.order_priority,
            }
            for a in all_artifacts
        ]
    )
    return {
        "compiler_version": COMPILER_VERSION,
        "manifest_hash": manifest_hash,
        "approved_records_compiled": len(approved_records),
        "skipped_unapproved_eligible": skipped_unapproved,
        "compiled_log_count": len(logs_only),
        "total_artifacts": len(all_artifacts),
        "max_conservative_words": max((a.conservative_word_count for a in logs_only), default=0),
        "category_distribution": cat_dist,
        "folder_instruction_chars": folder_instr_art.char_count,
    }


def load_compiled_artifacts(registry: KnowledgeRegistry) -> list[CompiledArtifact]:
    rows = registry.db.conn.execute(
        "SELECT * FROM compiled_artifacts ORDER BY order_priority ASC, artifact_key ASC;"
    ).fetchall()
    return [
        CompiledArtifact(
            artifact_key=str(r["artifact_key"]),
            logical_id=str(r["logical_id"]),
            revision_number=int(r["revision_number"]),
            artifact_kind=str(r["artifact_kind"]),
            category=str(r["category"]),
            title=str(r["title"]),
            body=str(r["body"]),
            part_index=int(r["part_index"]),
            part_total=int(r["part_total"]),
            word_count=int(r["word_count"]),
            conservative_word_count=int(r["conservative_word_count"]),
            char_count=int(r["char_count"]),
            payload_hash=str(r["payload_hash"]),
            normalized_payload_hash=str(r["normalized_payload_hash"]),
            compiler_version=str(r["compiler_version"]),
            order_priority=int(r["order_priority"]),
        )
        for r in rows
    ]


def export_manifest_json(artifacts: list[CompiledArtifact]) -> str:
    data = {
        "compiler_version": COMPILER_VERSION,
        "artifact_count": len(artifacts),
        "artifacts": [a.model_dump() for a in artifacts],
    }
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
