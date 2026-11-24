"""Privacy, sensitivity, and explicit inclusion/exclusion enforcement engine (Invariant 10)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stream_memory_manager.models import (
    EXCLUDED_PRIVACY_CLASSES,
    InclusionDecision,
    PrivacyClassification,
    PrivacyViolationError,
    RecordStatus,
)
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import (
    detect_prompt_injection,
    detect_secrets,
    normalize_for_scanning,
)

CATEGORY_ALLOW_RE = re.compile(r"^[A-Z0-9_ -]{1,32}$")

# Generic, repo-safe sensitive-domain scanners (zero third-party personal/collaborator names hardcoded).
# Optional owner-local rules can be loaded from gitignored `data/local_privacy_rules.json`.
HARD_BLOCK_PATTERNS: tuple[tuple[str, PrivacyClassification, re.Pattern[str]], ...] = (
    (
        "ssn_or_tax_id",
        PrivacyClassification.EXCLUDED_PRIVACY,
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    (
        "payment_card_number",
        PrivacyClassification.EXCLUDED_PRIVACY,
        re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{3,4}\b"),
    ),
    (
        "exact_account_balance",
        PrivacyClassification.EXCLUDED_PRIVACY,
        re.compile(
            r"(?i)\b(?:checking|savings|bank|brokerage|roth\s*ira|401k|credit\s*card)\s+"
            r"(?:account\s+)?(?:balance|value|loss|deficit)\s*(?:is|of|:|=)\s*\$?\d[\d,]*(?:\.\d{2})?\b"
        ),
    ),
    (
        "identity_theft_chronology",
        PrivacyClassification.EXCLUDED_PRIVACY,
        re.compile(
            r"(?i)\b(?:identity[- ]theft\s+chronology|fraudulent\s+account\s+number|police\s+report\s+#\d+)\b"
        ),
    ),
    (
        "private_appendix_marker",
        PrivacyClassification.EXCLUDED_PRIVACY,
        re.compile(
            r"(?i)(?:^#+\s*private\s+(?:review\s+)?appendix\b|\bPRIVATE_APPENDIX_DO_NOT_IMPORT\b)",
            re.M,
        ),
    ),
    (
        "operational_tailscale_host",
        PrivacyClassification.EXCLUDED_SECURITY,
        re.compile(r"\b[a-z0-9-]+\.[a-z0-9-]+\.ts\.net\b", re.I),
    ),
    (
        "operational_ntfy_topic",
        PrivacyClassification.EXCLUDED_SECURITY,
        re.compile(r"https?://ntfy\.sh/[A-Za-z0-9_-]{8,}", re.I),
    ),
    (
        "ssh_private_config",
        PrivacyClassification.EXCLUDED_SECURITY,
        re.compile(r"(?i)\b(?:IdentityFile\s+~/.ssh/|ssh-rsa\s+AAAA|ssh-ed25519\s+AAAA)\b"),
    ),
    (
        "raw_cookie_or_har",
        PrivacyClassification.EXCLUDED_SECURITY,
        re.compile(
            r"(?i)\b(?:storageState\.json|__Secure-next-auth\.session-token|session_cookie\s*=)\b"
        ),
    ),
    (
        "coursework_automation",
        PrivacyClassification.EXCLUDED_PRIVACY,
        re.compile(r"(?i)\b(?:smartbook-automation|packback_live_score\.user\.js)\b"),
    ),
    (
        "sandbar_forensic_dossier",
        PrivacyClassification.EXCLUDED_CONFIDENTIAL,
        re.compile(r"(?i)\bSANDBAR_STREAM_COMPLETE_HANDOFF\b"),
    ),
    (
        "raw_medical_measurements",
        PrivacyClassification.EXCLUDED_PRIVACY,
        re.compile(
            r"(?i)\b(?:blood\s+pressure\s+\d{2,3}/\d{2,3}|A1C\s*(?:is|of|:|=)\s*\d|prescription\s+dosage\s+\d+\s*mg)\b"
        ),
    ),
)

REVIEW_FLAG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "adhd_formal_diagnosis_claim",
        re.compile(
            r"(?i)\b(?:formally\s+diagnosed\s+with\s+ADHD|confirmed\s+ADHD\s+diagnosis|has\s+clinical\s+ADHD)\b"
        ),
    ),
    (
        "tracking_number_candidate",
        re.compile(r"\b(?:9400|9205|9261|9300|1Z)[A-Z0-9]{14,24}\b"),
    ),
    (
        "private_phone_number",
        re.compile(r"(?:\(\d{3}\)\s*\d{3}[-.\s]\d{4}|\b(?:\+1[-.\s]?)?\d{3}[-.]\d{3}[-.]\d{4}\b)"),
    ),
    (
        "private_email_address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
)

BLOCKED_EXPORT_CLASSES: frozenset[PrivacyClassification] = frozenset(
    {
        *EXCLUDED_PRIVACY_CLASSES,
        PrivacyClassification.GENERALIZED_REQUIRED,
        PrivacyClassification.SENSITIVE_REVIEW_REQUIRED,
    }
)


@dataclass(frozen=True)
class PrivacyFinding:
    rule_id: str
    severity: str  # "HARD_BLOCK" | "REVIEW"
    classification: PrivacyClassification
    message: str


def load_local_privacy_rules(
    rules_path: Path | None = None,
) -> list[tuple[str, PrivacyClassification, re.Pattern[str]]]:
    """Load optional owner-local custom hard-block patterns from a gitignored JSON file."""
    if rules_path is None or not rules_path.exists():
        return []
    try:
        raw = json.loads(rules_path.read_text(encoding="utf-8"))
        entries = raw.get("hard_block_patterns", []) if isinstance(raw, dict) else []
        loaded: list[tuple[str, PrivacyClassification, re.Pattern[str]]] = []
        for item in entries:
            if not isinstance(item, dict):
                continue
            rid = str(item.get("rule_id", "")).strip()
            pat = str(item.get("regex", "")).strip()
            cls_name = str(
                item.get("classification", PrivacyClassification.EXCLUDED_CONFIDENTIAL.value)
            )
            if rid and pat:
                loaded.append((rid, PrivacyClassification(cls_name), re.compile(pat, re.I)))
        return loaded
    except Exception:
        return []


def scan_text_privacy(
    title: str,
    body: str,
    *,
    extra_fields: list[str] | None = None,
    local_rules_path: Path | None = None,
) -> list[PrivacyFinding]:
    """Deterministically inspect ALL rendered text after NFKC + zero-width normalization."""
    parts = [title, body, *(extra_fields or [])]
    combined = normalize_for_scanning("\n".join(p for p in parts if p))
    findings: list[PrivacyFinding] = []

    for secret_rule in detect_secrets(combined):
        findings.append(
            PrivacyFinding(
                rule_id=f"secret:{secret_rule}",
                severity="HARD_BLOCK",
                classification=PrivacyClassification.EXCLUDED_SECURITY,
                message=f"Detected credential/secret pattern ({secret_rule})",
            )
        )

    all_hard_rules = list(HARD_BLOCK_PATTERNS) + load_local_privacy_rules(local_rules_path)
    for rule_id, pclass, pattern in all_hard_rules:
        if pattern.search(combined):
            findings.append(
                PrivacyFinding(
                    rule_id=rule_id,
                    severity="HARD_BLOCK",
                    classification=pclass,
                    message=f"Matched hard-block privacy/security exclusion rule ({rule_id})",
                )
            )

    for rule_id, pattern in REVIEW_FLAG_PATTERNS:
        if pattern.search(combined):
            if rule_id == "adhd_formal_diagnosis_claim" and re.search(
                r"(?i)\b(?:no|not|without)\s+(?:a\s+)?(?:formal|confirmed|clinical)\s+(?:ADHD\s+)?diagnosis\b",
                combined,
            ):
                continue
            findings.append(
                PrivacyFinding(
                    rule_id=rule_id,
                    severity="REVIEW",
                    classification=PrivacyClassification.SENSITIVE_REVIEW_REQUIRED,
                    message=f"Requires human privacy review ({rule_id})",
                )
            )

    for inj in detect_prompt_injection(combined):
        findings.append(
            PrivacyFinding(
                rule_id=f"prompt_injection:{inj['rule_id']}",
                severity="REVIEW",
                classification=PrivacyClassification.SENSITIVE_REVIEW_REQUIRED,
                message=f"Instruction-like prompt-injection text found in data ({inj['rule_id']})",
            )
        )

    return findings


def _record_extra_rendered_fields(rec: dict[str, Any]) -> list[str]:
    extras: list[str] = [
        str(rec.get("category") or ""),
        str(rec.get("effective_date") or ""),
        str(rec.get("observed_date") or ""),
        str(rec.get("last_confirmed_date") or ""),
        str(rec.get("update_triggers") or ""),
    ]
    aliases = rec.get("search_aliases") or []
    extras.extend(str(a) for a in aliases)
    return extras


def evaluate_registry_privacy(
    registry: KnowledgeRegistry, *, local_rules_path: Path | None = None
) -> dict[str, Any]:
    """Audit every record (including metadata fields) and enforce fail-closed privacy classifications."""
    records = registry.list_records()
    summary: dict[str, Any] = {
        "total_records": len(records),
        "hard_blocked": [],
        "needs_review": [],
        "approved_clean": [],
        "excluded": [],
    }

    for rec in records:
        lid = str(rec["logical_id"])
        findings = scan_text_privacy(
            str(rec["title"]),
            str(rec["body"]),
            extra_fields=_record_extra_rendered_fields(rec),
            local_rules_path=local_rules_path,
        )
        hard_blocks = [f for f in findings if f.severity == "HARD_BLOCK"]
        reviews = [f for f in findings if f.severity == "REVIEW"]

        if hard_blocks:
            worst_class = hard_blocks[0].classification
            registry.set_decision(
                lid,
                privacy_classification=worst_class,
                inclusion_decision=InclusionDecision.EXCLUDED,
                destination_eligible=False,
            )
            registry.record_issue(
                issue_id=f"priv_block_{lid}",
                issue_type="PRIVACY_HARD_BLOCK",
                severity="CRITICAL",
                logical_id=lid,
                summary=f"Record {lid} blocked from export: {', '.join(f.rule_id for f in hard_blocks)}",
                details={"rules": [f.rule_id for f in hard_blocks]},
            )
            summary["hard_blocked"].append(
                {
                    "logical_id": lid,
                    "title": rec["title"],
                    "rules": [f.rule_id for f in hard_blocks],
                }
            )
            continue

        pclass = PrivacyClassification(str(rec["privacy_classification"]))
        decision = InclusionDecision(str(rec["inclusion_decision"]))

        if pclass in EXCLUDED_PRIVACY_CLASSES or decision == InclusionDecision.EXCLUDED:
            if rec["destination_eligible"]:
                registry.set_decision(lid, destination_eligible=False)
            summary["excluded"].append(
                {"logical_id": lid, "title": rec["title"], "classification": pclass.value}
            )
            continue

        if reviews:
            # Force PENDING_REVIEW whenever unreviewed prompt-injection or sensitive patterns appear
            # unless already explicitly classified as PERSONAL_APPROVED/PUBLIC_SAFE AND APPROVED.
            has_injection = any(f.rule_id.startswith("prompt_injection:") for f in reviews)
            if has_injection or decision != InclusionDecision.APPROVED:
                registry.set_decision(
                    lid,
                    privacy_classification=PrivacyClassification.SENSITIVE_REVIEW_REQUIRED,
                    inclusion_decision=InclusionDecision.PENDING_REVIEW,
                )
            registry.record_issue(
                issue_id=f"priv_review_{lid}",
                issue_type="PRIVACY_REVIEW_REQUIRED",
                severity="WARNING",
                logical_id=lid,
                summary=f"Record {lid} flagged for privacy review: {', '.join(f.rule_id for f in reviews)}",
                details={"rules": [f.rule_id for f in reviews]},
            )
            summary["needs_review"].append(
                {"logical_id": lid, "title": rec["title"], "rules": [f.rule_id for f in reviews]}
            )
            continue

        if decision == InclusionDecision.APPROVED and rec["destination_eligible"]:
            if pclass in (
                PrivacyClassification.GENERALIZED_REQUIRED,
                PrivacyClassification.SENSITIVE_REVIEW_REQUIRED,
            ):
                summary["needs_review"].append(
                    {"logical_id": lid, "title": rec["title"], "rules": [pclass.value]}
                )
            else:
                summary["approved_clean"].append({"logical_id": lid, "title": rec["title"]})
        elif decision == InclusionDecision.PENDING_REVIEW:
            summary["needs_review"].append(
                {"logical_id": lid, "title": rec["title"], "rules": ["pending_explicit_inclusion"]}
            )
        else:
            summary["excluded"].append(
                {"logical_id": lid, "title": rec["title"], "classification": pclass.value}
            )

    return summary


def assert_payload_safe(
    title: str,
    body: str,
    *,
    label: str = "<payload>",
    local_rules_path: Path | None = None,
) -> None:
    """Direct payload-level Invariant 10 scan on finalized outgoing text (logs, index, folder instruction, briefing)."""
    findings = scan_text_privacy(title, body, local_rules_path=local_rules_path)
    blocking = [
        f
        for f in findings
        if f.severity == "HARD_BLOCK" or f.rule_id.startswith("prompt_injection:")
    ]
    if blocking:
        raise PrivacyViolationError(
            f"Outgoing payload {label} blocked by privacy/injection gate: {[f.rule_id for f in blocking]}",
            details={"label": label, "rules": [f.rule_id for f in blocking]},
        )


def assert_record_exportable(rec: dict[str, Any], *, local_rules_path: Path | None = None) -> None:
    """Invariant 10 gate: fail closed if an excluded, unapproved, or tainted record attempts export."""
    lid = str(rec.get("logical_id", "<unknown>"))
    cat = str(rec.get("category", "")).strip().upper()
    if not CATEGORY_ALLOW_RE.match(cat):
        raise PrivacyViolationError(
            f"Record {lid} has invalid category {cat!r} (must match ^[A-Z0-9_ -]{{1,32}}$)",
            details={"logical_id": lid, "category": cat},
        )
    status = RecordStatus(str(rec.get("status", RecordStatus.ACTIVE.value)))
    if status in (RecordStatus.SUPERSEDED, RecordStatus.ARCHIVED):
        raise PrivacyViolationError(
            f"Record {lid} has non-exportable status {status.value}",
            details={"logical_id": lid, "status": status.value},
        )
    pclass = PrivacyClassification(str(rec.get("privacy_classification")))
    if pclass in BLOCKED_EXPORT_CLASSES:
        raise PrivacyViolationError(
            f"Record {lid} has non-exportable privacy classification {pclass.value}",
            details={"logical_id": lid, "privacy_classification": pclass.value},
        )
    decision = InclusionDecision(str(rec.get("inclusion_decision")))
    if decision != InclusionDecision.APPROVED:
        raise PrivacyViolationError(
            f"Record {lid} is not explicitly approved for inclusion (decision={decision.value})",
            details={"logical_id": lid, "inclusion_decision": decision.value},
        )
    if not rec.get("destination_eligible", False):
        raise PrivacyViolationError(
            f"Record {lid} is marked destination_eligible=False",
            details={"logical_id": lid},
        )
    findings = scan_text_privacy(
        str(rec.get("title", "")),
        str(rec.get("body", "")),
        extra_fields=_record_extra_rendered_fields(rec),
        local_rules_path=local_rules_path,
    )
    blocking = [
        f
        for f in findings
        if f.severity == "HARD_BLOCK" or f.rule_id.startswith("prompt_injection:")
    ]
    if blocking:
        raise PrivacyViolationError(
            f"Record {lid} tripped privacy/security/injection gate: {[f.rule_id for f in blocking]}",
            details={"logical_id": lid, "rules": [f.rule_id for f in blocking]},
        )
