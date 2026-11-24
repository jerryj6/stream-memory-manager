"""Core domain models, enumerations, exit codes, and error taxonomy."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ExitCode(IntEnum):
    """Stable, agent-parseable CLI exit codes."""

    SUCCESS = 0
    VALIDATION_ERROR = 2
    APPROVAL_REQUIRED = 3
    AUTHORIZATION_REQUIRED = 4
    BLOCKED_CONFLICT = 5
    PARTIAL_VERIFICATION = 6
    AMBIGUOUS_REMOTE_OUTCOME = 7
    TEMPORARY_FAILURE = 8
    PERMANENT_FAILURE = 9


class ExecutionMode(StrEnum):
    MOCK = "mock"
    DRY_RUN = "dry-run"
    LIVE = "live"


class RecordStatus(StrEnum):
    ACTIVE = "ACTIVE"
    HISTORICAL = "HISTORICAL"
    SUPERSEDED = "SUPERSEDED"
    DORMANT = "DORMANT"
    PROPOSED = "PROPOSED"
    DRAFT = "DRAFT"
    ARCHIVED = "ARCHIVED"


class EvidenceClass(StrEnum):
    USER_CONFIRMED = "USER_CONFIRMED"
    USER_DIRECTED = "USER_DIRECTED"
    ARTIFACT_INSPECTED = "ARTIFACT_INSPECTED"
    INDEPENDENTLY_VERIFIED = "INDEPENDENTLY_VERIFIED"
    AGENT_REPORTED = "AGENT_REPORTED"
    PROPOSED = "PROPOSED"
    INFERRED = "INFERRED"
    HISTORICAL = "HISTORICAL"
    SUPERSEDED = "SUPERSEDED"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"


EVIDENCE_RANK: dict[EvidenceClass, int] = {
    EvidenceClass.USER_CONFIRMED: 100,
    EvidenceClass.USER_DIRECTED: 95,
    EvidenceClass.INDEPENDENTLY_VERIFIED: 90,
    EvidenceClass.ARTIFACT_INSPECTED: 80,
    EvidenceClass.AGENT_REPORTED: 50,
    EvidenceClass.PROPOSED: 40,
    EvidenceClass.INFERRED: 30,
    EvidenceClass.HISTORICAL: 20,
    EvidenceClass.SUPERSEDED: 10,
    EvidenceClass.UNKNOWN: 5,
    EvidenceClass.CONFLICTED: 0,
}


class PrivacyClassification(StrEnum):
    PUBLIC_SAFE = "PUBLIC_SAFE"
    PERSONAL_APPROVED = "PERSONAL_APPROVED"
    GENERALIZED_REQUIRED = "GENERALIZED_REQUIRED"
    SENSITIVE_REVIEW_REQUIRED = "SENSITIVE_REVIEW_REQUIRED"
    EXCLUDED_PRIVACY = "EXCLUDED_PRIVACY"
    EXCLUDED_SECURITY = "EXCLUDED_SECURITY"
    EXCLUDED_CONFIDENTIAL = "EXCLUDED_CONFIDENTIAL"
    EXCLUDED_IRRELEVANT = "EXCLUDED_IRRELEVANT"


EXCLUDED_PRIVACY_CLASSES: frozenset[PrivacyClassification] = frozenset(
    {
        PrivacyClassification.EXCLUDED_PRIVACY,
        PrivacyClassification.EXCLUDED_SECURITY,
        PrivacyClassification.EXCLUDED_CONFIDENTIAL,
        PrivacyClassification.EXCLUDED_IRRELEVANT,
    }
)


class InclusionDecision(StrEnum):
    APPROVED = "APPROVED"
    PENDING_REVIEW = "PENDING_REVIEW"
    EXCLUDED = "EXCLUDED"


class RemoteSyncStatus(StrEnum):
    UNSYNCED = "UNSYNCED"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
    VERIFIED = "VERIFIED"
    UNCERTAIN = "UNCERTAIN"
    NEEDS_MANUAL_UPDATE = "NEEDS_MANUAL_UPDATE"
    NEEDS_MANUAL_DELETION = "NEEDS_MANUAL_DELETION"
    CONFLICTED = "CONFLICTED"


class RelationType(StrEnum):
    SUBCOMPONENT_OF = "SUBCOMPONENT_OF"
    SUPERSEDES = "SUPERSEDES"
    SUPPLEMENTS = "SUPPLEMENTS"
    RELATES_TO = "RELATES_TO"
    CONTRADICTS = "CONTRADICTS"
    DEPENDS_ON = "DEPENDS_ON"
    CORRECTS = "CORRECTS"
    DERIVED_FROM = "DERIVED_FROM"


class OperationType(StrEnum):
    RESOLVE_OR_CREATE_FOLDER = "RESOLVE_OR_CREATE_FOLDER"
    CREATE_LOG = "CREATE_LOG"
    UPDATE_LOG = "UPDATE_LOG"
    MOVE_LOG_TO_FOLDER = "MOVE_LOG_TO_FOLDER"
    UPDATE_FOLDER_INSTRUCTION = "UPDATE_FOLDER_INSTRUCTION"
    SET_BRIEFING = "SET_BRIEFING"
    MANUAL_REPLACEMENT_REQUIRED = "MANUAL_REPLACEMENT_REQUIRED"
    MANUAL_DELETION_REQUIRED = "MANUAL_DELETION_REQUIRED"


class OperationState(StrEnum):
    PLANNED = "PLANNED"
    APPROVED = "APPROVED"
    READY = "READY"
    REQUEST_PREPARED = "REQUEST_PREPARED"
    REQUEST_IN_FLIGHT = "REQUEST_IN_FLIGHT"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
    VERIFIED = "VERIFIED"
    RETRY_WAIT = "RETRY_WAIT"
    PAUSED_AUTHORIZATION = "PAUSED_AUTHORIZATION"
    PAUSED_RATE_LIMIT = "PAUSED_RATE_LIMIT"
    PAUSED_VERIFICATION_AUTH = "PAUSED_VERIFICATION_AUTH"
    PAUSED_VERIFICATION_RATE_LIMIT = "PAUSED_VERIFICATION_RATE_LIMIT"
    UNCERTAIN_REMOTE_OUTCOME = "UNCERTAIN_REMOTE_OUTCOME"
    CONFLICTED = "CONFLICTED"
    BLOCKED = "BLOCKED"
    FAILED_CONFIRMED = "FAILED_CONFIRMED"
    CANCELLED_BEFORE_WRITE = "CANCELLED_BEFORE_WRITE"


class PlanStatus(StrEnum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    PAUSED = "PAUSED"
    BLOCKED = "BLOCKED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    COMPLETED = "COMPLETED"
    INVALIDATED = "INVALIDATED"
    CANCELLED = "CANCELLED"


class ErrorClass(StrEnum):
    NONE = "NONE"
    READ_TRANSIENT = "READ_TRANSIENT"
    PRE_DISPATCH_FAILURE = "PRE_DISPATCH_FAILURE"
    CONFIRMED_REJECTED_WRITE = "CONFIRMED_REJECTED_WRITE"
    POTENTIALLY_COMMITTED_WRITE = "POTENTIALLY_COMMITTED_WRITE"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    RATE_LIMIT_ERROR = "RATE_LIMIT_ERROR"
    TRANSPORT_INTERRUPTION = "TRANSPORT_INTERRUPTION"
    VALIDATION_PERMANENT = "VALIDATION_PERMANENT"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    ACCOUNT_MISMATCH = "ACCOUNT_MISMATCH"
    CONFLICT_ERROR = "CONFLICT_ERROR"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class ClaimRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    claim_id: str
    logical_id: str
    revision_number: int
    claim_text: str
    evidence_class: EvidenceClass
    effective_date: str | None = None
    observed_date: str | None = None
    source_ref: str | None = None
    status: str = "ACTIVE"


class MemoryRecordInput(BaseModel):
    logical_id: str
    title: str
    category: str
    body: str
    logical_group: str = "General"
    canonical_subject: str = ""
    status: RecordStatus = RecordStatus.ACTIVE
    evidence_class: EvidenceClass = EvidenceClass.USER_CONFIRMED
    effective_date: str | None = None
    observed_date: str | None = None
    last_confirmed_date: str | None = None
    source_refs: list[str] = Field(default_factory=list)
    source_hashes: list[str] = Field(default_factory=list)
    search_aliases: list[str] = Field(default_factory=list)
    related_ids: list[str] = Field(default_factory=list)
    update_triggers: str | None = None
    privacy_classification: PrivacyClassification = PrivacyClassification.PERSONAL_APPROVED
    inclusion_decision: InclusionDecision = InclusionDecision.PENDING_REVIEW
    destination_eligible: bool = True
    claims: list[dict[str, Any]] = Field(default_factory=list)


class CompiledArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    artifact_key: str
    logical_id: str
    revision_number: int
    artifact_kind: str  # "log" | "folder_instruction" | "briefing"
    category: str
    title: str
    body: str
    part_index: int = 1
    part_total: int = 1
    word_count: int
    conservative_word_count: int
    char_count: int
    payload_hash: str
    normalized_payload_hash: str
    compiler_version: str
    order_priority: int = 500


class RequestBudget(BaseModel):
    max_planned_writes: int = 150
    max_verification_attempts_per_op: int = 4
    max_reconciliation_requests: int = 100
    max_retries_per_op: int = 3
    max_consecutive_errors: int = 3
    max_unresolved_operations: int = 1
    batch_size: int = 10


class StreamMemoryError(Exception):
    """Base application error with stable error class and CLI exit code."""

    def __init__(
        self,
        message: str,
        *,
        error_class: ErrorClass = ErrorClass.UNKNOWN_ERROR,
        exit_code: ExitCode = ExitCode.PERMANENT_FAILURE,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_class = error_class
        self.exit_code = exit_code
        self.details = details or {}


class DatabaseCorruptionError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.PERMANENT_FAILURE,
            details=details,
        )


class ApprovalRequiredError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.APPROVAL_REQUIRED,
            details=details,
        )


class AuthorizationRequiredError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.AUTHENTICATION_ERROR,
            exit_code=ExitCode.AUTHORIZATION_REQUIRED,
            details=details,
        )


class AccountMismatchError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.ACCOUNT_MISMATCH,
            exit_code=ExitCode.BLOCKED_CONFLICT,
            details=details,
        )


class SchemaDriftError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.SCHEMA_MISMATCH,
            exit_code=ExitCode.BLOCKED_CONFLICT,
            details=details,
        )


class LockContentionError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.CONFLICT_ERROR,
            exit_code=ExitCode.BLOCKED_CONFLICT,
            details=details,
        )


class PrivacyViolationError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
            details=details,
        )


class IllegalStateTransitionError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.PERMANENT_FAILURE,
            details=details,
        )


class RateLimitError(StreamMemoryError):
    def __init__(
        self,
        message: str,
        *,
        retry_after_seconds: float | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.RATE_LIMIT_ERROR,
            exit_code=ExitCode.TEMPORARY_FAILURE,
            details={**(details or {}), "retry_after_seconds": retry_after_seconds},
        )
        self.retry_after_seconds = retry_after_seconds


class AmbiguousWriteError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.POTENTIALLY_COMMITTED_WRITE,
            exit_code=ExitCode.AMBIGUOUS_REMOTE_OUTCOME,
            details=details,
        )


class CapabilityUnsupportedError(StreamMemoryError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message,
            error_class=ErrorClass.UNSUPPORTED_CAPABILITY,
            exit_code=ExitCode.BLOCKED_CONFLICT,
            details=details,
        )


def utc_now_iso(now: datetime | None = None) -> str:
    """Return an ISO-8601 UTC timestamp string."""

    dt = now or datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
