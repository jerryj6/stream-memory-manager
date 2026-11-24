"""Source material ingestion parsers (Markdown archives, plain text, structured JSON).

All ingested content is strictly treated as UNTRUSTED DATA (Section 10.3).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from stream_memory_manager.models import (
    ErrorClass,
    EvidenceClass,
    ExitCode,
    InclusionDecision,
    MemoryRecordInput,
    PrivacyClassification,
    RecordStatus,
    RelationType,
    StreamMemoryError,
)
from stream_memory_manager.privacy import scan_text_privacy
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import detect_prompt_injection, sha256_text

CHATGPT_V2_HEADING_RE = re.compile(r"^#\s+(\d{2}-\d{2})\s+[—–-]\s+(.+?)\s*$")
NUMBERED_MASTER_HEADING_RE = re.compile(r"^#\s+(?:\*\*)?(\d{2,3})\s+[—–-]\s+(.+?)(?:\*\*)?\s*$")
TECH_SUPP_HEADING_RE = re.compile(r"^#\s+(T\d{2})\s+[—–-]\s+(.+?)\s*$")
PROJECT_REC_HEADING_RE = re.compile(r"^###\s+`?(P\d{2})`?\s+[—–-]\s+(.+?)\s*$")
GENERIC_MD_HEADING_RE = re.compile(r"^#\s+(.+?)\s*$")

V2_CATEGORY_PREFIX_MAP: dict[str, str] = {
    "00": "CORE",
    "01": "PERSONAL",
    "02": "PREFERENCES",
    "03": "CURRENT",
    "04": "PROJECTS",
    "05": "ACADEMICS",
    "06": "INFRASTRUCTURE",
    "07": "PREFERENCES",
    "08": "PERSONAL",
    "09": "PERSONAL",
    "10": "HISTORY",
    "11": "CURRENT",
    "12": "WORKFLOWS",
    "13": "HISTORY",
}

TECH_CATEGORY_MAP: dict[str, tuple[str, str]] = {
    "T01": ("CORE", "Technical Briefing & Instructions"),
    "T02": ("ENGINEERING", "Agent-First Philosophy"),
    "T03": ("ENGINEERING", "Technical Capabilities"),
    "T04": ("CIVIC", "Political Information Systems"),
    "T05": ("RESEARCH", "Computational Mathematics"),
    "T06": ("SOFTWARE", "Algorithmic Solvers & Applications"),
    "T07": ("HARDWARE", "Hardware & Native Systems"),
    "T08": ("RESEARCH", "Quantitative Modeling"),
    "T09": ("INFRASTRUCTURE", "Self-Hosted & Infrastructure Systems"),
    "T10": ("ENGINEERING", "Local AI & Agent Tooling"),
    "T11": ("RESEARCH", "Simulation & Applied Research"),
    "T12": ("CURRENT", "Technical Priorities & Dormant Work"),
}


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug[:48] or "record"


def _infer_evidence_class(meta_text: str, body: str) -> EvidenceClass:
    combined = f"{meta_text}\n{body}".lower()
    if (
        "directly inspected" in combined
        or "artifact-verified" in combined
        or "artifact-grounded" in combined
    ):
        return EvidenceClass.ARTIFACT_INSPECTED
    if "independently verified" in combined or "externally verified" in combined:
        return EvidenceClass.INDEPENDENTLY_VERIFIED
    if "explicit migration instruction" in combined or "standing engineering directive" in combined:
        return EvidenceClass.USER_DIRECTED
    if "proposed architecture only" in combined or "proposed" in meta_text.lower():
        return EvidenceClass.PROPOSED
    if re.search(r"\b(?:status\s*:\s*superseded|superseded\s+by)\b", meta_text.lower()):
        return EvidenceClass.SUPERSEDED
    if "historical" in meta_text.lower():
        return EvidenceClass.HISTORICAL
    if "agent-reported" in combined:
        return EvidenceClass.AGENT_REPORTED
    if "user-reported" in combined or "confirmed" in meta_text.lower():
        return EvidenceClass.USER_CONFIRMED
    return EvidenceClass.USER_CONFIRMED


def _infer_status(meta_text: str, body: str) -> RecordStatus:
    m = meta_text.lower()
    if re.search(r"\b(?:status\s*:\s*superseded|superseded\s+by)\b", m):
        return RecordStatus.SUPERSEDED
    if "dormant" in m and "active" not in m:
        return RecordStatus.DORMANT
    if "historical" in m and "active" not in m:
        return RecordStatus.HISTORICAL
    if "proposed" in m and "implemented" not in m:
        return RecordStatus.PROPOSED
    if "targeted retrieval produced no further detail" in body.lower():
        return RecordStatus.HISTORICAL
    return RecordStatus.ACTIVE


def _extract_claims(
    body: str, default_evidence: EvidenceClass, observed_date: str | None, source_ref: str
) -> list[dict[str, Any]]:
    """Extract lightweight claim-level evidence classifications from structured sentences/bullets."""
    claims: list[dict[str, Any]] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "---":
            continue
        if stripped.startswith("- ") and len(stripped) > 20:
            text = stripped[2:].strip()
            low = text.lower()
            ev = default_evidence
            if "proposed" in low or "not yet implemented" in low or "not wired" in low:
                ev = EvidenceClass.PROPOSED
            elif "independently verified" in low or "lrat" in low:
                ev = EvidenceClass.INDEPENDENTLY_VERIFIED
            elif "directly inspected" in low or "physical" in low:
                ev = EvidenceClass.ARTIFACT_INSPECTED
            elif "agent-reported" in low or "reported as" in low:
                ev = EvidenceClass.AGENT_REPORTED
            elif "unknown" in low or "unverified" in low:
                ev = EvidenceClass.UNKNOWN
            elif "superseded" in low or "abandoned" in low:
                ev = EvidenceClass.HISTORICAL
            claims.append(
                {
                    "claim_text": text[:300],
                    "evidence_class": ev.value,
                    "observed_date": observed_date,
                    "source_ref": source_ref,
                }
            )
            if len(claims) >= 12:
                break
    return claims


def parse_chatgpt_v2_markdown(
    content: str, *, source_id: str, content_sha: str, default_approve: bool = False
) -> tuple[list[MemoryRecordInput], list[tuple[str, str, RelationType, str]]]:
    """Parse structured ChatGPT V2 consolidated archive (`# XX-YY — Title` sections)."""
    lines = content.splitlines()
    sections: list[tuple[str, str, list[str]]] = []
    cur_id: str | None = None
    cur_title: str | None = None
    cur_lines: list[str] = []

    for line in lines:
        m = CHATGPT_V2_HEADING_RE.match(line)
        if m:
            if cur_id is not None and cur_title is not None:
                sections.append((cur_id, cur_title, cur_lines))
            cur_id, cur_title = m.group(1), m.group(2).strip()
            cur_lines = []
        elif cur_id is not None:
            cur_lines.append(line)
    if cur_id is not None and cur_title is not None:
        sections.append((cur_id, cur_title, cur_lines))

    records: list[MemoryRecordInput] = []
    relationships: list[tuple[str, str, RelationType, str]] = []

    for sec_id, raw_title, sec_lines in sections:
        meta: dict[str, str] = {}
        body_lines: list[str] = []
        in_meta = True
        for raw_line in sec_lines:
            stripped = raw_line.strip()
            if in_meta and stripped == "":
                if meta:
                    in_meta = False
                continue
            if in_meta and stripped.startswith("- ") and ":" in stripped:
                key, val = stripped[2:].split(":", 1)
                meta[key.strip().lower()] = val.strip()
                continue
            in_meta = False
            if stripped == "---":
                continue
            body_lines.append(raw_line)

        body = "\n".join(body_lines).strip()
        if not body:
            continue

        mod_num = sec_id.split("-")[0]
        cat = V2_CATEGORY_PREFIX_MAP.get(mod_num, "PERSONAL")
        logical_id = f"v2_{sec_id.replace('-', '_')}"
        aliases = [
            a.strip()
            for a in re.split(r"[;,]", meta.get("search aliases / entities", ""))
            if a.strip()
        ]
        related_raw = [
            r.strip()
            for r in re.split(r"[;,]", meta.get("related records", ""))
            if re.match(r"^\d{2}-\d{2}$", r.strip())
        ]
        related_ids = [f"v2_{r.replace('-', '_')}" for r in related_raw]
        for rel_id in related_ids:
            relationships.append(
                (logical_id, rel_id, RelationType.RELATES_TO, "ChatGPT V2 related link")
            )

        meta_summary = " | ".join(
            [meta.get("status", ""), meta.get("evidence", ""), meta.get("category", "")]
        )
        ev_class = _infer_evidence_class(meta_summary, body)
        status = _infer_status(meta_summary, body)
        effective_date = meta.get("date range")
        observed_date = meta.get("export observation") or "2026-11-23"
        last_confirmed = meta.get("last evidence / confirmation")
        update_triggers = meta.get("update triggers")

        # Empty historical stubs in V2 are kept in local registry as HISTORICAL & ineligible for Stream
        is_empty_stub = (
            "targeted retrieval produced no further detail" in body.lower()
            or "no recovered platform, code, or scope" in body.lower()
        )
        # Master navigation indices from V2 are superseded by our compiler's unified CORE index
        is_v2_nav = sec_id in ("00-01", "00-05")
        dest_eligible = not (is_empty_stub or is_v2_nav)

        findings = scan_text_privacy(raw_title, body)
        has_hard_block = any(f.severity == "HARD_BLOCK" for f in findings)
        priv_class = (
            findings[0].classification
            if has_hard_block
            else (
                PrivacyClassification.SENSITIVE_REVIEW_REQUIRED
                if findings
                else PrivacyClassification.PERSONAL_APPROVED
            )
        )
        if has_hard_block:
            decision = InclusionDecision.EXCLUDED
            dest_eligible = False
        elif default_approve and not findings and dest_eligible:
            decision = InclusionDecision.APPROVED
        else:
            decision = InclusionDecision.PENDING_REVIEW

        records.append(
            MemoryRecordInput(
                logical_id=logical_id,
                title=raw_title,
                category=cat,
                logical_group=meta.get("category", cat),
                canonical_subject=raw_title,
                body=body,
                status=RecordStatus.HISTORICAL if is_empty_stub else status,
                evidence_class=ev_class,
                effective_date=effective_date,
                observed_date=observed_date,
                last_confirmed_date=last_confirmed,
                source_refs=[f"{source_id}#{sec_id}"],
                source_hashes=[content_sha],
                search_aliases=aliases,
                related_ids=related_ids,
                update_triggers=update_triggers,
                privacy_classification=priv_class,
                inclusion_decision=decision,
                destination_eligible=dest_eligible,
                claims=_extract_claims(body, ev_class, observed_date, f"{source_id}#{sec_id}"),
            )
        )
    return records, relationships


def parse_tech_supplement_markdown(
    content: str, *, source_id: str, content_sha: str, default_approve: bool = False
) -> tuple[list[MemoryRecordInput], list[tuple[str, str, RelationType, str]]]:
    """Parse structured Antigravity technical supplement (`# T01`-`# T12`)."""
    lines = content.splitlines()
    sections: list[tuple[str, str, list[str]]] = []
    cur_id: str | None = None
    cur_title: str | None = None
    cur_lines: list[str] = []

    for line in lines:
        m = TECH_SUPP_HEADING_RE.match(line)
        if m:
            if cur_id is not None and cur_title is not None:
                sections.append((cur_id, cur_title, cur_lines))
            cur_id, cur_title = m.group(1), m.group(2).strip()
            cur_lines = []
        elif cur_id is not None:
            cur_lines.append(line)
    if cur_id is not None and cur_title is not None:
        sections.append((cur_id, cur_title, cur_lines))

    records: list[MemoryRecordInput] = []
    relationships: list[tuple[str, str, RelationType, str]] = []

    for sec_id, raw_title, sec_lines in sections:
        meta: dict[str, str] = {}
        body_lines: list[str] = []
        in_meta = True
        for raw_line in sec_lines:
            stripped = raw_line.strip()
            if in_meta and stripped == "":
                if meta:
                    in_meta = False
                continue
            if in_meta and stripped.startswith("- ") and ":" in stripped:
                key, val = stripped[2:].split(":", 1)
                meta[key.strip().lower()] = val.strip()
                continue
            in_meta = False
            if stripped == "---":
                continue
            body_lines.append(raw_line)

        body = "\n".join(body_lines).strip()
        if not body:
            continue

        cat, group_name = TECH_CATEGORY_MAP.get(sec_id, ("ENGINEERING", "Technical Supplement"))
        logical_id = f"tech_{sec_id.lower()}"
        aliases = [a.strip() for a in re.split(r"[;,]", meta.get("search terms", "")) if a.strip()]
        date_meta = meta.get("date range") or meta.get("reference date") or "2026-11-23"
        observed_date = "2026-11-23"
        ev_class = _infer_evidence_class(date_meta + " " + meta.get("scope", ""), body)
        status = _infer_status(date_meta, body)

        findings = scan_text_privacy(raw_title, body)
        has_hard_block = any(f.severity == "HARD_BLOCK" for f in findings)
        priv_class = (
            findings[0].classification
            if has_hard_block
            else (
                PrivacyClassification.SENSITIVE_REVIEW_REQUIRED
                if findings
                else PrivacyClassification.PERSONAL_APPROVED
            )
        )
        dest_eligible = not has_hard_block
        if has_hard_block:
            decision = InclusionDecision.EXCLUDED
        elif default_approve and not findings:
            decision = InclusionDecision.APPROVED
        else:
            decision = InclusionDecision.PENDING_REVIEW

        records.append(
            MemoryRecordInput(
                logical_id=logical_id,
                title=raw_title,
                category=cat,
                logical_group=group_name,
                canonical_subject=raw_title,
                body=body,
                status=status,
                evidence_class=ev_class,
                effective_date=date_meta.split("|")[0].strip(),
                observed_date=observed_date,
                last_confirmed_date="2026-11-23",
                source_refs=[f"{source_id}#{sec_id}"],
                source_hashes=[content_sha],
                search_aliases=aliases,
                privacy_classification=priv_class,
                inclusion_decision=decision,
                destination_eligible=dest_eligible,
                claims=_extract_claims(body, ev_class, observed_date, f"{source_id}#{sec_id}"),
            )
        )
    return records, relationships


def _infer_category_from_title(sec_num: str, title: str) -> str:
    low = title.lower()
    if sec_num in ("00", "01", "35") or "operating instructions" in low or "briefing" in low:
        return "CORE"
    if "preference" in low or "communication" in low or "display" in low or "personal care" in low:
        return "PREFERENCES"
    if (
        "engineering" in low
        or "collaboration" in low
        or "local ai" in low
        or "principles" in low
        or "capabilities" in low
    ):
        return "ENGINEERING"
    if "civic" in low or "political" in low:
        return "CIVIC"
    if (
        "mathematics" in low
        or "quantitative" in low
        or "research" in low
        or "applied research" in low
    ):
        return "RESEARCH"
    if "solver" in low or "software" in low or "application" in low or "bridge" in low:
        return "SOFTWARE"
    if "hardware" in low or "keyboard" in low:
        return "HARDWARE"
    if "infrastructure" in low or "self-hosted" in low or "wearable" in low or "stream" in low:
        return "INFRASTRUCTURE"
    if (
        "education" in low
        or "fellowship" in low
        or "internship" in low
        or "career" in low
        or "campus" in low
    ):
        return "ACADEMICS"
    if "priority" in low or "priorities" in low or "open loop" in low or "current" in low:
        return "CURRENT"
    if "timeline" in low or "historical" in low or "dormant" in low:
        return "HISTORY"
    if "workflow" in low or "recurring" in low:
        return "WORKFLOWS"
    return "PERSONAL"


def parse_numbered_master_markdown(
    content: str,
    *,
    source_id: str,
    content_sha: str,
    default_approve: bool = False,
) -> list[MemoryRecordInput]:
    """Parse `# 00 — Title` ... `# NN — Title` consolidated docs and `STREAM_MEMORY_EXPORT v1` web replies."""
    # Unwrap optional markdown fence and strip standardized STREAM_MEMORY_EXPORT boundary markers
    stripped = content.strip()
    if stripped.startswith("```"):
        fence_lines = stripped.splitlines()
        if len(fence_lines) >= 2 and fence_lines[-1].strip().startswith("```"):
            stripped = "\n".join(fence_lines[1:-1])

    doc_observed_date = "2026-11-23"
    date_hdr = re.search(r"STREAM_MEMORY_EXPORT\s+v1[^>\n]*date:\s*(\d{4}-\d{2}-\d{2})", stripped)
    if date_hdr:
        doc_observed_date = date_hdr.group(1)

    lines = [
        ln
        for ln in stripped.splitlines()
        if not re.match(r"^\s*\\?<!--\s*(?:END_)?STREAM_MEMORY_EXPORT\b.*-->\s*$", ln)
    ]
    sections: list[tuple[str, str, list[str]]] = []
    cur_num: str | None = None
    cur_title: str | None = None
    cur_lines: list[str] = []

    for line in lines:
        m = NUMBERED_MASTER_HEADING_RE.match(line)
        if m:
            if cur_num is not None and cur_title is not None:
                sections.append((cur_num, cur_title, cur_lines))
            cur_num = m.group(1)
            cur_title = m.group(2).strip()
            cur_lines = []
        elif cur_num is not None:
            cur_lines.append(line)

    if cur_num is not None and cur_title is not None:
        sections.append((cur_num, cur_title, cur_lines))

    records: list[MemoryRecordInput] = []
    for sec_num, title, raw_body_lines in sections:
        explicit_cat: str | None = None
        explicit_status: str | None = None
        explicit_observed: str | None = None
        cleaned_lines: list[str] = []
        in_meta_hdr = True
        for ln in raw_body_lines:
            if in_meta_hdr:
                s = ln.strip().rstrip("\\").strip()
                if not s:
                    continue
                cm = re.match(r"^(?:\*\*)?Category(?:\*\*)?:\s*(.+)$", s, re.IGNORECASE)
                sm = re.match(r"^(?:\*\*)?Status(?:\*\*)?:\s*(.+)$", s, re.IGNORECASE)
                om = re.match(
                    r"^(?:\*\*)?Observed(?:\*\*)?:\s*(\d{4}-\d{2}-\d{2})$", s, re.IGNORECASE
                )
                if cm:
                    explicit_cat = _sanitize_untrusted_category(cm.group(1).strip("*\\ "))
                    continue
                if sm:
                    explicit_status = sm.group(1).strip("*\\ ").upper()
                    continue
                if om:
                    explicit_observed = om.group(1).strip("*\\ ")
                    continue
                in_meta_hdr = False
            cleaned_lines.append(ln)

        body = "\n".join(cleaned_lines).strip()
        if not body:
            continue
        lid = f"ctx_{sec_num}_{_slugify(title)[:24]}"
        category = explicit_cat or _infer_category_from_title(sec_num, title)
        header_probe = "\n".join(cleaned_lines[:8])
        status = _infer_status(f"{explicit_status or ''}\n{title}\n{header_probe}", body)
        ev = _infer_evidence_class(f"{title}\n{header_probe}", body)
        if sec_num == "00":
            ev = EvidenceClass.USER_DIRECTED
            status = RecordStatus.ACTIVE
        obs_date = explicit_observed or doc_observed_date

        findings = scan_text_privacy(title, body, extra_fields=[category])
        has_hard_block = any(f.severity == "HARD_BLOCK" for f in findings)
        priv = (
            findings[0].classification
            if has_hard_block
            else (
                PrivacyClassification.SENSITIVE_REVIEW_REQUIRED
                if findings
                else PrivacyClassification.PERSONAL_APPROVED
            )
        )
        decision = (
            InclusionDecision.EXCLUDED
            if has_hard_block
            else (
                InclusionDecision.APPROVED
                if (default_approve and not findings)
                else InclusionDecision.PENDING_REVIEW
            )
        )
        records.append(
            MemoryRecordInput(
                logical_id=lid,
                title=title,
                category=category,
                logical_group=f"Master Context ({category})",
                canonical_subject=title,
                body=body,
                status=status,
                evidence_class=ev,
                effective_date=obs_date,
                observed_date=obs_date,
                last_confirmed_date=obs_date,
                source_refs=[f"{source_id}#{sec_num}"],
                source_hashes=[content_sha],
                privacy_classification=priv,
                inclusion_decision=decision,
                destination_eligible=not has_hard_block,
                claims=_extract_claims(body, ev, obs_date, f"{source_id}#{sec_num}"),
            )
        )
    return records


def parse_generic_markdown(
    content: str,
    *,
    source_id: str,
    content_sha: str,
    source_label: str,
    default_approve: bool = False,
) -> list[MemoryRecordInput]:
    """Parse arbitrary Markdown files split by H1 headings (or single record if none)."""
    lines = content.splitlines()
    sections: list[tuple[str, list[str]]] = []
    cur_title: str | None = None
    cur_lines: list[str] = []

    for line in lines:
        m = GENERIC_MD_HEADING_RE.match(line)
        if m:
            if cur_title is not None:
                sections.append((cur_title, cur_lines))
            cur_title = m.group(1).strip()
            cur_lines = []
        else:
            if cur_title is None:
                cur_title = source_label
            cur_lines.append(line)
    if cur_title is not None:
        sections.append((cur_title, cur_lines))

    records: list[MemoryRecordInput] = []
    for idx, (title, sec_lines) in enumerate(sections, start=1):
        body = "\n".join(sec_lines).strip()
        if not body:
            continue
        lid = f"doc_{_slugify(source_label)}_{idx:02d}_{_slugify(title)[:24]}"
        findings = scan_text_privacy(title, body)
        has_hard_block = any(f.severity == "HARD_BLOCK" for f in findings)
        priv = (
            findings[0].classification
            if has_hard_block
            else (
                PrivacyClassification.SENSITIVE_REVIEW_REQUIRED
                if findings
                else PrivacyClassification.PERSONAL_APPROVED
            )
        )
        decision = (
            InclusionDecision.EXCLUDED
            if has_hard_block
            else (
                InclusionDecision.APPROVED
                if (default_approve and not findings)
                else InclusionDecision.PENDING_REVIEW
            )
        )
        records.append(
            MemoryRecordInput(
                logical_id=lid,
                title=title,
                category="GENERAL",
                logical_group=source_label,
                canonical_subject=title,
                body=body,
                status=RecordStatus.ACTIVE,
                evidence_class=EvidenceClass.USER_CONFIRMED,
                source_refs=[f"{source_id}#sec_{idx}"],
                source_hashes=[content_sha],
                privacy_classification=priv,
                inclusion_decision=decision,
                destination_eligible=not has_hard_block,
            )
        )
    return records


RESERVED_LOGICAL_ID_PREFIXES: tuple[str, ...] = ("core_knowledge_index", "meta_")
PRIVATE_PATH_RE = re.compile(r"(?i)(?:private[-_ ]?(?:appendix|review)|^private$)")


def _sanitize_untrusted_category(raw_cat: str) -> str:
    cleaned = re.sub(r"[^A-Z0-9_ -]+", "", raw_cat.strip().upper())[:32].strip()
    return cleaned or "GENERAL"


def _reject_reserved_logical_id(lid: str) -> str:
    low = lid.strip().lower()
    if any(low == p or low.startswith(p) for p in RESERVED_LOGICAL_ID_PREFIXES):
        raise StreamMemoryError(
            f"Untrusted source attempted to spoof reserved internal logical_id: {lid!r}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    return lid


def parse_json_source(
    content: str, *, source_id: str, content_sha: str, default_approve: bool = False
) -> list[MemoryRecordInput]:
    """Parse structured JSON source strictly as UNTRUSTED DATA (strips caller approval/privacy claims)."""
    try:
        raw = json.loads(content)
    except json.JSONDecodeError as exc:
        raise StreamMemoryError(
            f"Malformed JSON source: {exc}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        ) from exc

    items = raw.get("records", []) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise StreamMemoryError(
            "JSON source must be an array of records or an object with a 'records' array",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    records: list[MemoryRecordInput] = []
    for idx, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", f"Record {idx}")).strip()
        body = str(item.get("body", "")).strip()
        if not body:
            continue
        lid = _reject_reserved_logical_id(
            str(item.get("logical_id") or f"json_{idx:03d}_{_slugify(title)[:24]}")
        )
        cat = _sanitize_untrusted_category(str(item.get("category", "GENERAL")))
        aliases = [str(a) for a in item.get("search_aliases", [])]
        triggers = item.get("update_triggers")
        extra_fields = [
            cat,
            str(item.get("effective_date") or ""),
            str(item.get("observed_date") or ""),
            str(item.get("last_confirmed_date") or ""),
            str(triggers or ""),
            *aliases,
        ]
        # NEVER trust caller-supplied inclusion_decision or privacy_classification in untrusted JSON!
        findings = scan_text_privacy(title, body, extra_fields=extra_fields)
        has_hard_block = any(f.severity == "HARD_BLOCK" for f in findings)
        priv = (
            findings[0].classification
            if has_hard_block
            else (
                PrivacyClassification.SENSITIVE_REVIEW_REQUIRED
                if findings
                else PrivacyClassification.PERSONAL_APPROVED
            )
        )
        if has_hard_block:
            decision = InclusionDecision.EXCLUDED
        elif default_approve and not findings:
            decision = InclusionDecision.APPROVED
        else:
            decision = InclusionDecision.PENDING_REVIEW

        # Cap untrusted JSON evidence_class so untrusted input cannot forge USER_CONFIRMED supersession
        raw_ev = EvidenceClass(str(item.get("evidence_class", EvidenceClass.AGENT_REPORTED.value)))
        capped_ev = (
            raw_ev
            if raw_ev
            in (
                EvidenceClass.AGENT_REPORTED,
                EvidenceClass.PROPOSED,
                EvidenceClass.INFERRED,
                EvidenceClass.HISTORICAL,
                EvidenceClass.UNKNOWN,
            )
            else EvidenceClass.AGENT_REPORTED
        )

        records.append(
            MemoryRecordInput(
                logical_id=lid,
                title=title,
                category=cat,
                logical_group=str(item.get("logical_group", "Imported JSON")),
                canonical_subject=str(item.get("canonical_subject", title)),
                body=body,
                status=RecordStatus(str(item.get("status", RecordStatus.ACTIVE.value))),
                evidence_class=capped_ev,
                effective_date=item.get("effective_date"),
                observed_date=item.get("observed_date"),
                last_confirmed_date=None,
                source_refs=[f"{source_id}#{lid}"],
                source_hashes=[content_sha],
                search_aliases=aliases,
                related_ids=[str(r) for r in item.get("related_ids", [])],
                update_triggers=str(triggers) if triggers else None,
                privacy_classification=priv,
                inclusion_decision=decision,
                destination_eligible=not has_hard_block,
                claims=item.get("claims", []),
            )
        )
    return records


def ingest_file(
    registry: KnowledgeRegistry,
    file_path: Path,
    *,
    source_format: str = "auto",
    default_approve: bool = False,
) -> dict[str, Any]:
    """Ingest a Markdown, plain-text, or JSON source file into the canonical registry."""
    resolved = file_path.resolve()
    if not resolved.exists() or not resolved.is_file():
        raise StreamMemoryError(
            f"Source file not found: {resolved}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    # Privacy guard: never automatically ingest private-review appendices or files in private/ directories
    # (Skip macOS system root symlink prefix /private/{var,tmp,etc} when resolving temp/system paths)
    parts_to_check = resolved.parts
    if (
        len(parts_to_check) >= 3
        and parts_to_check[0] == "/"
        and parts_to_check[1] == "private"
        and parts_to_check[2] in {"var", "tmp", "etc"}
    ):
        parts_to_check = parts_to_check[3:]
    if any(PRIVATE_PATH_RE.search(part) for part in parts_to_check):
        raise StreamMemoryError(
            f"Refusing to automatically ingest sensitive private-review appendix/path: {resolved.name}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    content = resolved.read_text(encoding="utf-8")
    content_sha = sha256_text(content)
    ext = resolved.suffix.lower()

    detected_format = source_format
    if detected_format == "auto":
        if ext == ".json":
            detected_format = "json"
        elif any(CHATGPT_V2_HEADING_RE.match(line) for line in content.splitlines()[:120]):
            detected_format = "chatgpt_v2_md"
        elif any(NUMBERED_MASTER_HEADING_RE.match(line) for line in content.splitlines()[:120]):
            detected_format = "numbered_master_md"
        elif any(TECH_SUPP_HEADING_RE.match(line) for line in content.splitlines()[:120]):
            detected_format = "tech_supplement_md"
        elif ext in (".md", ".markdown"):
            detected_format = "markdown"
        else:
            detected_format = "text"

    injection_hits = detect_prompt_injection(content)
    source_id = registry.register_source(
        source_path=str(resolved),
        source_label=resolved.stem,
        source_format=detected_format,
        content=content,
        metadata={
            "filename": resolved.name,
            "prompt_injection_warning_count": len(injection_hits),
        },
    )

    relationships: list[tuple[str, str, RelationType, str]] = []
    if detected_format == "chatgpt_v2_md":
        parsed_records, relationships = parse_chatgpt_v2_markdown(
            content, source_id=source_id, content_sha=content_sha, default_approve=default_approve
        )
    elif detected_format == "numbered_master_md":
        parsed_records = parse_numbered_master_markdown(
            content, source_id=source_id, content_sha=content_sha, default_approve=default_approve
        )
    elif detected_format == "tech_supplement_md":
        parsed_records, relationships = parse_tech_supplement_markdown(
            content, source_id=source_id, content_sha=content_sha, default_approve=default_approve
        )
    elif detected_format == "json":
        parsed_records = parse_json_source(
            content, source_id=source_id, content_sha=content_sha, default_approve=default_approve
        )
    elif detected_format == "markdown":
        parsed_records = parse_generic_markdown(
            content,
            source_id=source_id,
            content_sha=content_sha,
            source_label=resolved.stem,
            default_approve=default_approve,
        )
    else:
        txt_title = resolved.stem.replace("_", " ").replace("-", " ").title()
        txt_body = content.strip()
        txt_findings = scan_text_privacy(txt_title, txt_body)
        txt_hard_block = any(f.severity == "HARD_BLOCK" for f in txt_findings)
        txt_priv = (
            txt_findings[0].classification
            if txt_hard_block
            else (
                PrivacyClassification.SENSITIVE_REVIEW_REQUIRED
                if txt_findings
                else PrivacyClassification.PERSONAL_APPROVED
            )
        )
        txt_decision = (
            InclusionDecision.EXCLUDED
            if txt_hard_block
            else (
                InclusionDecision.APPROVED
                if (default_approve and not txt_findings)
                else InclusionDecision.PENDING_REVIEW
            )
        )
        parsed_records = [
            MemoryRecordInput(
                logical_id=f"txt_{_slugify(resolved.stem)}",
                title=txt_title,
                category="GENERAL",
                logical_group="Plain Text Import",
                canonical_subject=resolved.stem,
                body=txt_body,
                evidence_class=EvidenceClass.USER_CONFIRMED,
                source_refs=[source_id],
                source_hashes=[content_sha],
                privacy_classification=txt_priv,
                inclusion_decision=txt_decision,
                destination_eligible=not txt_hard_block,
            )
        ]

    created = 0
    revised = 0
    unchanged = 0
    with registry.db.transaction():
        for rec in parsed_records:
            res = registry.upsert_record(rec)
            if res["action"] == "created":
                created += 1
            elif res["action"] == "revised":
                revised += 1
            else:
                unchanged += 1

        for src_lid, tgt_lid, rel_type, note in relationships:
            registry.add_relationship(src_lid, tgt_lid, rel_type, note=note)

        if injection_hits:
            registry.record_issue(
                issue_id=f"inj_{source_id}",
                issue_type="PROMPT_INJECTION_DETECTED",
                severity="WARNING",
                summary=f"Source {resolved.name} contains {len(injection_hits)} instruction-like pattern(s); treated strictly as untrusted data.",
                details={"source_id": source_id, "findings": injection_hits[:10]},
            )

    return {
        "source_id": source_id,
        "source_path": str(resolved),
        "detected_format": detected_format,
        "content_sha256": content_sha,
        "records_parsed": len(parsed_records),
        "created": created,
        "revised": revised,
        "unchanged": unchanged,
        "prompt_injection_warnings": len(injection_hits),
    }
