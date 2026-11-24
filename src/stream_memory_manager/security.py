"""Security utilities: normalization, secret redaction, atomic 0600 writes, path & endpoint guards."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from stream_memory_manager.models import ErrorClass, ExecutionMode, ExitCode, StreamMemoryError

ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("basic_auth", re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
    ),
    ("openai_key", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    (
        "kv_secret",
        re.compile(
            r"(?i)(['\"]?\b(?:access_token|refresh_token|id_token|client_secret|client_assertion|"
            r"authorization|password|api_key|x-api-key|cookie|set-cookie|code_verifier|"
            r"session_token|token|secret)\b['\"]?\s*[:=]\s*['\"]?)([^\s'\",;}{]{6,})"
        ),
    ),
)

PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_instructions",
        re.compile(
            r"(?i)\b(?:ignore|disregard|override|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions?\b"
        ),
    ),
    (
        "bypass_approval",
        re.compile(
            r"(?i)\b(?:bypass|skip|disable)\s+(?:the\s+)?(?:approval|privacy|confirmation|verification|rate[- ]?limit)\b"
        ),
    ),
    (
        "auto_approve",
        re.compile(
            r"(?i)\b(?:auto[- ]?approve|execute\s+immediately\s+without\s+approval|upload\s+private\s+appendix)\b"
        ),
    ),
    (
        "exfiltrate_tokens",
        re.compile(
            r"(?i)\b(?:print|dump|export|exfiltrate|reveal)\s+(?:all\s+)?(?:oauth|access|refresh)?\s*(?:tokens?|credentials?|secrets?|keychain)\b"
        ),
    ),
    (
        "tool_override",
        re.compile(r"(?i)\b(?:system\s+prompt|developer\s+override|new\s+root\s+directive)\s*:"),
    ),
)

TRUSTED_SANDBAR_HOST = "api.sandbar.com"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")


def normalize_for_scanning(text: str) -> str:
    """NFKC-normalize and strip invisible zero-width/bidi characters to prevent regex evasion."""
    return ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", text))


def redact_secrets(text: str) -> str:
    """Redact credentials, JSON-encoded tokens, and authorization headers from strings."""
    result = text
    for name, pattern in SECRET_PATTERNS:
        if name == "kv_secret":
            result = pattern.sub(r"\1[REDACTED]", result)
        elif name == "bearer_token":
            result = pattern.sub("Bearer [REDACTED]", result)
        elif name == "basic_auth":
            result = pattern.sub("Basic [REDACTED]", result)
        else:
            result = pattern.sub(f"[REDACTED:{name}]", result)
    return result


def redact_object(obj: Any) -> Any:
    """Recursively redact sensitive keys and string values in JSON-serializable objects."""
    sensitive_keys = {
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "session_token",
        "client_secret",
        "client_assertion",
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "api_key",
        "x-api-key",
        "secret",
        "code_verifier",
        "code",
    }
    if isinstance(obj, dict):
        sanitized: dict[str, Any] = {}
        for k, v in obj.items():
            if str(k).lower() in sensitive_keys:
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_object(v)
        return sanitized
    if isinstance(obj, list):
        return [redact_object(item) for item in obj]
    if isinstance(obj, str):
        return redact_secrets(obj)
    return obj


def detect_prompt_injection(text: str) -> list[dict[str, str]]:
    """Detect instruction-like prompt-injection payloads after Unicode/zero-width normalization."""
    normalized = normalize_for_scanning(text)
    findings: list[dict[str, str]] = []
    for rule_id, pattern in PROMPT_INJECTION_PATTERNS:
        for match in pattern.finditer(normalized):
            snippet = normalized[
                max(0, match.start() - 20) : min(len(normalized), match.end() + 20)
            ]
            findings.append(
                {
                    "rule_id": rule_id,
                    "matched": match.group(0),
                    "context": redact_secrets(snippet).replace("\n", " "),
                }
            )
    return findings


def detect_secrets(text: str) -> list[str]:
    """Return rule names for any credential/secret patterns detected after normalization."""
    normalized = normalize_for_scanning(text)
    hits: list[str] = []
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(normalized):
            hits.append(name)
    return sorted(set(hits))


def ensure_private_dir(path: Path) -> Path:
    """Create directory with owner-only permissions (0700), rejecting symlinks."""
    if path.is_symlink():
        raise StreamMemoryError(
            f"Refusing to operate on symlinked private directory: {path}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def set_private_file_permissions(path: Path) -> None:
    """Restrict regular file permissions to owner read/write (0600), refusing symlinks."""
    if path.is_symlink():
        raise StreamMemoryError(
            f"Refusing to chmod symlinked path: {path}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    if path.exists():
        os.chmod(path, 0o600)


def atomic_write_private_text(path: Path, content: str) -> Path:
    """Atomically write sensitive text with 0600 permissions from creation (zero umask TOCTOU/symlink race)."""
    ensure_private_dir(path.parent)
    if path.is_symlink():
        raise StreamMemoryError(
            f"Refusing to overwrite symlink: {path}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except BaseException:
        if tmp_path.exists():
            tmp_path.unlink()
        raise
    return path


def safe_resolve_under(base_dir: Path, relative_or_child: str | Path) -> Path:
    """Resolve a path strictly inside `base_dir`, preventing path traversal and symlink escapes."""
    base = base_dir.resolve()
    raw_target = base / Path(relative_or_child)
    if raw_target.is_symlink():
        raise StreamMemoryError(
            f"Symlink target blocked: {relative_or_child!r}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    candidate = raw_target.resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise StreamMemoryError(
            f"Path traversal blocked: {relative_or_child!r} escapes {base}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        ) from exc
    return candidate


def validate_safe_label(label: str) -> str:
    if not SAFE_LABEL_RE.match(label):
        raise StreamMemoryError(
            f"Invalid label {label!r}: must match ^[A-Za-z0-9_-]{{1,48}}$",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    return label


def validate_endpoint_url(
    url: str,
    *,
    allow_localhost_http: bool = False,
    expected_mode: ExecutionMode | None = None,
) -> str:
    """Validate MCP/OAuth endpoint URL and enforce strict mode-to-endpoint isolation."""
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise StreamMemoryError(
            f"Unsupported endpoint scheme: {parsed.scheme!r}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise StreamMemoryError(
            f"Endpoint URL missing hostname: {url!r}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    is_local = host in LOOPBACK_HOSTS

    if expected_mode == ExecutionMode.MOCK:
        if not is_local:
            raise StreamMemoryError(
                f"Mock mode refuses non-loopback endpoint {url!r} to prevent accidental live writes.",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        if not allow_localhost_http and parsed.scheme == "http":
            raise StreamMemoryError(
                f"Plaintext localhost HTTP requires explicit allow_localhost_http=True: {url!r}",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
    elif expected_mode == ExecutionMode.LIVE and (
        parsed.scheme != "https" or host != TRUSTED_SANDBAR_HOST or allow_localhost_http
    ):
        raise StreamMemoryError(
            f"Live mode strictly requires https://{TRUSTED_SANDBAR_HOST} without localhost bypass; got {url!r}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    if parsed.scheme == "http" and not (allow_localhost_http and is_local):
        raise StreamMemoryError(
            f"Plaintext HTTP endpoint prohibited outside localhost mock mode: {url!r}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    if not allow_localhost_http and host != TRUSTED_SANDBAR_HOST:
        raise StreamMemoryError(
            f"Unexpected live MCP endpoint host {host!r}; expected {TRUSTED_SANDBAR_HOST!r}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    return url


def canonical_account_scope(
    *,
    server_url: str,
    account_id: str | None = None,
    profile_name: str = "default",
) -> str:
    """Canonical account-level key for BOTH single-writer locking and rate limiting.

    Excludes `target_folder_name` so two plans targeting the same Sandbar account share
    the same exclusive writer lock and 1 req/s rate scheduler!
    """
    parsed = urlparse(server_url)
    origin = f"{parsed.scheme}://{parsed.netloc}".lower()
    subject = account_id.strip() if account_id and account_id.strip() else f"profile:{profile_name}"
    return f"acct_{canonical_json_hash({'origin': origin, 'subject': subject})[:20]}"


def canonical_json_hash(data: Any) -> str:
    """Compute a deterministic SHA-256 hex digest of a JSON-serializable structure."""
    encoded = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
