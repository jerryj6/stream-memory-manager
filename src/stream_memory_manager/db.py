"""Durable SQLite persistence with WAL, FULL sync, migrations, corruption detection, and online backups."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

from stream_memory_manager.models import (
    DatabaseCorruptionError,
    ErrorClass,
    ExitCode,
    StreamMemoryError,
    utc_now_iso,
)
from stream_memory_manager.security import (
    atomic_write_private_text,
    ensure_private_dir,
    safe_resolve_under,
    set_private_file_permissions,
    validate_safe_label,
)

SCHEMA_VERSION = 1

SCHEMA_V1_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    source_path TEXT NOT NULL,
    source_label TEXT NOT NULL,
    source_format TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    trust_level TEXT NOT NULL DEFAULT 'UNTRUSTED_DATA',
    ingested_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS memory_records (
    logical_id TEXT PRIMARY KEY,
    current_revision INTEGER NOT NULL DEFAULT 1,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    logical_group TEXT NOT NULL DEFAULT 'General',
    canonical_subject TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    privacy_classification TEXT NOT NULL DEFAULT 'PERSONAL_APPROVED',
    inclusion_decision TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
    destination_eligible INTEGER NOT NULL DEFAULT 1,
    sync_status TEXT NOT NULL DEFAULT 'UNSYNCED',
    remote_id TEXT,
    remote_folder_id TEXT,
    remote_last_update_ts INTEGER,
    verified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS record_revisions (
    revision_id TEXT PRIMARY KEY,
    logical_id TEXT NOT NULL REFERENCES memory_records(logical_id) ON DELETE RESTRICT,
    revision_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    content_checksum TEXT NOT NULL,
    effective_date TEXT,
    observed_date TEXT,
    last_confirmed_date TEXT,
    evidence_class TEXT NOT NULL,
    search_aliases_json TEXT NOT NULL DEFAULT '[]',
    update_triggers TEXT,
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    source_hashes_json TEXT NOT NULL DEFAULT '[]',
    superseded_by_revision_id TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(logical_id, revision_number)
);

CREATE TABLE IF NOT EXISTS record_claims (
    claim_id TEXT PRIMARY KEY,
    logical_id TEXT NOT NULL REFERENCES memory_records(logical_id) ON DELETE RESTRICT,
    revision_number INTEGER NOT NULL,
    claim_text TEXT NOT NULL,
    evidence_class TEXT NOT NULL,
    effective_date TEXT,
    observed_date TEXT,
    source_ref TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS record_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_logical_id TEXT NOT NULL REFERENCES memory_records(logical_id) ON DELETE RESTRICT,
    target_logical_id TEXT NOT NULL REFERENCES memory_records(logical_id) ON DELETE RESTRICT,
    relation_type TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(source_logical_id, target_logical_id, relation_type)
);

CREATE TABLE IF NOT EXISTS reconciliation_issues (
    issue_id TEXT PRIMARY KEY,
    issue_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    logical_id TEXT,
    related_logical_id TEXT,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'OPEN',
    resolution_note TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS compiled_artifacts (
    artifact_key TEXT PRIMARY KEY,
    logical_id TEXT NOT NULL,
    revision_number INTEGER NOT NULL,
    artifact_kind TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    part_index INTEGER NOT NULL DEFAULT 1,
    part_total INTEGER NOT NULL DEFAULT 1,
    word_count INTEGER NOT NULL,
    conservative_word_count INTEGER NOT NULL,
    char_count INTEGER NOT NULL,
    payload_hash TEXT NOT NULL,
    normalized_payload_hash TEXT NOT NULL,
    compiler_version TEXT NOT NULL,
    order_priority INTEGER NOT NULL DEFAULT 500,
    compiled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capability_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    server_url TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    schema_fingerprint TEXT NOT NULL,
    sanitized_tools_json TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS account_bindings (
    binding_hash TEXT PRIMARY KEY,
    profile_name TEXT NOT NULL,
    server_url TEXT NOT NULL,
    issuer TEXT NOT NULL,
    account_id TEXT,
    account_id_verified INTEGER NOT NULL DEFAULT 0,
    target_folder_name TEXT NOT NULL DEFAULT 'Memory',
    target_folder_id TEXT,
    confirmed_by_user INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    bound_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    account_binding_hash TEXT NOT NULL,
    target_folder_name TEXT NOT NULL,
    target_folder_id TEXT,
    capability_fingerprint TEXT NOT NULL,
    compiler_version TEXT NOT NULL,
    status TEXT NOT NULL,
    budget_json TEXT NOT NULL,
    assumptions_json TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    approved_at TEXT,
    approval_actor TEXT,
    approval_note TEXT,
    invalidated_reason TEXT
);

CREATE TABLE IF NOT EXISTS operations (
    op_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES plans(plan_id) ON DELETE RESTRICT,
    sequence_num INTEGER NOT NULL,
    batch_num INTEGER NOT NULL,
    logical_id TEXT,
    revision_number INTEGER,
    op_type TEXT NOT NULL,
    account_binding_hash TEXT NOT NULL,
    target_folder_id TEXT,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    normalized_payload_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    verification_attempts INTEGER NOT NULL DEFAULT 0,
    last_error_class TEXT NOT NULL DEFAULT 'NONE',
    last_error_message TEXT,
    request_started_at TEXT,
    response_received_at TEXT,
    response_status TEXT,
    remote_id TEXT,
    remote_last_update_ts INTEGER,
    verified_postcondition_json TEXT,
    recovery_requirement TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(plan_id, sequence_num)
);

CREATE TABLE IF NOT EXISTS operation_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id TEXT NOT NULL REFERENCES operations(op_id) ON DELETE RESTRICT,
    plan_id TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    error_class TEXT NOT NULL DEFAULT 'NONE',
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limit_state (
    account_key TEXT PRIMARY KEY,
    next_allowed_epoch_ms INTEGER NOT NULL DEFAULT 0,
    consecutive_429s INTEGER NOT NULL DEFAULT 0,
    last_retry_after_s REAL,
    total_requests INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
    eval_id TEXT PRIMARY KEY,
    eval_type TEXT NOT NULL,
    dataset_name TEXT NOT NULL,
    results_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revisions_logical ON record_revisions(logical_id, revision_number);
CREATE INDEX IF NOT EXISTS idx_claims_logical ON record_claims(logical_id, revision_number);
CREATE INDEX IF NOT EXISTS idx_ops_plan_state ON operations(plan_id, state);
CREATE INDEX IF NOT EXISTS idx_events_op ON operation_events(op_id);
CREATE INDEX IF NOT EXISTS idx_issues_status ON reconciliation_issues(status);
"""


def _check_sqlite_header(db_path: Path) -> None:
    """Detect obviously corrupted non-SQLite files before opening so we never clobber them."""
    if not db_path.exists():
        return
    size = db_path.stat().st_size
    if size == 0:
        return
    with db_path.open("rb") as fh:
        header = fh.read(16)
    if header != b"SQLite format 3\x00":
        raise DatabaseCorruptionError(
            f"Database file {db_path} has an invalid SQLite header; refusing to overwrite or recreate."
        )


class Database:
    """Durable SQLite database manager with strict integrity checks and online backup."""

    def __init__(self, db_path: Path, *, read_only: bool = False) -> None:
        self.db_path = db_path.resolve()
        self.read_only = read_only
        if not read_only:
            ensure_private_dir(self.db_path.parent)
        _check_sqlite_header(self.db_path)
        self._conn = self._open_connection()
        self.verify_integrity()
        if not read_only:
            self._apply_migrations()
            self._harden_sqlite_files()

    def _harden_sqlite_files(self) -> None:
        set_private_file_permissions(self.db_path)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.db_path}{suffix}")
            if sidecar.exists() and not sidecar.is_symlink():
                set_private_file_permissions(sidecar)

    def _open_connection(self) -> sqlite3.Connection:
        try:
            if self.read_only:
                if not self.db_path.exists():
                    raise StreamMemoryError(
                        f"Database does not exist at {self.db_path}",
                        error_class=ErrorClass.VALIDATION_PERMANENT,
                        exit_code=ExitCode.VALIDATION_ERROR,
                    )
                encoded = quote(str(self.db_path), safe="/:")
                uri = f"file:{encoded}?mode=ro"
                conn = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
            else:
                if not self.db_path.exists():
                    fd = os.open(
                        str(self.db_path),
                        os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    )
                    os.close(fd)
                conn = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            if not self.read_only:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = FULL;")
            return conn
        except sqlite3.DatabaseError as exc:
            raise DatabaseCorruptionError(
                f"Failed to open SQLite database {self.db_path}: {exc}"
            ) from exc

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        self._conn.close()

    def verify_integrity(self) -> None:
        """Fail closed if SQLite reports any structural or page corruption."""
        try:
            rows = self._conn.execute("PRAGMA integrity_check;").fetchall()
        except sqlite3.DatabaseError as exc:
            raise DatabaseCorruptionError(
                f"SQLite integrity check raised error on {self.db_path}: {exc}"
            ) from exc
        if len(rows) != 1 or str(rows[0][0]).lower() != "ok":
            messages = [str(r[0]) for r in rows]
            raise DatabaseCorruptionError(
                f"SQLite integrity check failed for {self.db_path}: {messages}",
                details={"integrity_errors": messages},
            )

    def _apply_migrations(self) -> None:
        with self.transaction():
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                );
                """
            )
            row = self._conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations;"
            ).fetchone()
            current_version = int(row["v"]) if row else 0
            if current_version > SCHEMA_VERSION:
                raise StreamMemoryError(
                    f"Database schema version {current_version} is newer than supported {SCHEMA_VERSION}",
                    error_class=ErrorClass.VALIDATION_PERMANENT,
                    exit_code=ExitCode.PERMANENT_FAILURE,
                )
            if current_version < 1:
                for stmt in SCHEMA_V1_SQL.split(";"):
                    sql = stmt.strip()
                    if sql:
                        self._conn.execute(sql + ";")
                self._conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?);",
                    (
                        1,
                        utc_now_iso(),
                        "Initial canonical registry, plans, journal, and rate-limit schema",
                    ),
                )

    def schema_version(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations;"
        ).fetchone()
        return int(row["v"]) if row else 0

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Explicit IMMEDIATE transaction for atomic durable writes (supports nesting via savepoints)."""
        if self.read_only:
            raise StreamMemoryError(
                "Cannot open write transaction on read-only database",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        in_tx = self._conn.in_transaction
        if not in_tx:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                yield self._conn
                self._conn.execute("COMMIT;")
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK;")
                raise
        else:
            sp_name = f"sp_{id(self)}_{abs(hash(utc_now_iso())) % 100000}"
            self._conn.execute(f"SAVEPOINT {sp_name};")
            try:
                yield self._conn
                self._conn.execute(f"RELEASE SAVEPOINT {sp_name};")
            except BaseException:
                self._conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name};")
                self._conn.execute(f"RELEASE SAVEPOINT {sp_name};")
                raise

    def backup_to(self, destination_dir: Path, *, label: str = "manual") -> dict[str, Any]:
        """Create a consistent WAL-safe SQLite snapshot via the native Online Backup API."""
        self.verify_integrity()
        safe_label = validate_safe_label(label)
        dest_dir = ensure_private_dir(destination_dir.resolve())
        ts = utc_now_iso().replace(":", "").replace("-", "").replace(".", "_")
        backup_db = safe_resolve_under(dest_dir, f"stream_memory_{safe_label}_{ts}.db")
        meta_path = safe_resolve_under(dest_dir, f"stream_memory_{safe_label}_{ts}.backup.json")

        fd, tmp_name = tempfile.mkstemp(prefix=".bak_", suffix=".db", dir=str(dest_dir))
        os.fchmod(fd, 0o600)
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            dst_conn = sqlite3.connect(str(tmp_path))
            try:
                self._conn.backup(dst_conn)
                dst_conn.execute("PRAGMA synchronous = FULL;")
                dst_conn.commit()
                rows = dst_conn.execute("PRAGMA integrity_check;").fetchall()
                if len(rows) != 1 or str(rows[0][0]).lower() != "ok":
                    raise DatabaseCorruptionError(f"Backup integrity check failed: {rows}")
            finally:
                dst_conn.close()
            os.replace(tmp_path, backup_db)
            set_private_file_permissions(backup_db)
        except BaseException:
            if tmp_path.exists():
                tmp_path.unlink()
            raise

        sha256 = hashlib.sha256(backup_db.read_bytes()).hexdigest()
        counts = self.table_counts()
        metadata = {
            "backup_file": backup_db.name,
            "created_at": utc_now_iso(),
            "label": safe_label,
            "schema_version": self.schema_version(),
            "sha256": sha256,
            "byte_size": backup_db.stat().st_size,
            "table_counts": counts,
            "encryption_notice": "Unencrypted SQLite snapshot protected by OS filesystem permissions (0600); do not share publicly.",
        }
        atomic_write_private_text(meta_path, json.dumps(metadata, indent=2, sort_keys=True))
        return {
            "backup_path": str(backup_db),
            "metadata_path": str(meta_path),
            "metadata": metadata,
        }

    def list_managed_remote_ids(self) -> set[str]:
        """Return every remote Sandbar artifact ID ever created or tracked by this local DB."""
        rows = self._conn.execute(
            "SELECT DISTINCT remote_id FROM operations WHERE remote_id IS NOT NULL;"
        ).fetchall()
        rec_rows = self._conn.execute(
            "SELECT DISTINCT remote_id FROM memory_records WHERE remote_id IS NOT NULL;"
        ).fetchall()
        out = {str(r[0]) for r in rows if r[0]}
        out.update(str(r[0]) for r in rec_rows if r[0])
        return out

    def table_counts(self) -> dict[str, int]:
        queries = {
            "sources": "SELECT COUNT(*) AS c FROM sources;",
            "memory_records": "SELECT COUNT(*) AS c FROM memory_records;",
            "record_revisions": "SELECT COUNT(*) AS c FROM record_revisions;",
            "record_claims": "SELECT COUNT(*) AS c FROM record_claims;",
            "record_relationships": "SELECT COUNT(*) AS c FROM record_relationships;",
            "reconciliation_issues": "SELECT COUNT(*) AS c FROM reconciliation_issues;",
            "compiled_artifacts": "SELECT COUNT(*) AS c FROM compiled_artifacts;",
            "plans": "SELECT COUNT(*) AS c FROM plans;",
            "operations": "SELECT COUNT(*) AS c FROM operations;",
            "operation_events": "SELECT COUNT(*) AS c FROM operation_events;",
        }
        counts: dict[str, int] = {}
        for name, sql in queries.items():
            row = self._conn.execute(sql).fetchone()
            counts[name] = int(row["c"]) if row else 0
        return counts


REQUIRED_TABLES: frozenset[str] = frozenset(
    {
        "schema_migrations",
        "sources",
        "memory_records",
        "record_revisions",
        "compiled_artifacts",
        "plans",
        "operations",
        "operation_events",
        "rate_limit_state",
    }
)


def restore_backup(
    backup_db_path: Path,
    target_db_path: Path,
    *,
    expected_sha256: str | None = None,
    allow_unverified_checksum: bool = False,
) -> dict[str, Any]:
    """Verify backup checksum, SQLite integrity, and schema BEFORE touching target DB."""
    from stream_memory_manager.locking import AccountWriterLock

    backup_db_path = backup_db_path.resolve()
    target_db_path = target_db_path.resolve()
    if not backup_db_path.exists() or backup_db_path.is_symlink():
        raise StreamMemoryError(
            f"Backup file not found or invalid: {backup_db_path}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    _check_sqlite_header(backup_db_path)

    meta_candidate = backup_db_path.with_suffix(".backup.json")
    if expected_sha256 is None and meta_candidate.exists():
        meta = json.loads(meta_candidate.read_text(encoding="utf-8"))
        expected_sha256 = meta.get("sha256")
    if not expected_sha256 and not allow_unverified_checksum:
        raise DatabaseCorruptionError(
            "Backup checksum metadata (.backup.json or --expected-sha256) is required to restore safely."
        )

    ensure_private_dir(target_db_path.parent)
    restore_lock = AccountWriterLock(target_db_path.parent / "locks", "db_restore")
    with restore_lock:
        # Step 1: Copy backup into isolated 0600 temp file and hash the EXACT copied bytes (zero TOCTOU!)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".restore_tmp_", suffix=".db", dir=str(target_db_path.parent)
        )
        os.fchmod(fd, 0o600)
        os.close(fd)
        temp_target = Path(tmp_name)
        try:
            raw_bytes = backup_db_path.read_bytes()
            actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            if expected_sha256 and actual_sha256 != expected_sha256:
                raise DatabaseCorruptionError(
                    f"Backup SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
                )
            temp_target.write_bytes(raw_bytes)
            set_private_file_permissions(temp_target)

            # Step 2: Validate SQLite integrity, schema version, and required tables ON temp_target
            # BEFORE touching live target_db_path!
            encoded_tmp = quote(str(temp_target), safe="/:")
            verify_conn = sqlite3.connect(f"file:{encoded_tmp}?mode=ro", uri=True)
            try:
                rows = verify_conn.execute("PRAGMA integrity_check;").fetchall()
                if len(rows) != 1 or str(rows[0][0]).lower() != "ok":
                    raise DatabaseCorruptionError(f"Backup integrity check failed: {rows}")
                tables = {
                    str(r[0])
                    for r in verify_conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table';"
                    ).fetchall()
                }
                missing = REQUIRED_TABLES - tables
                if missing:
                    raise DatabaseCorruptionError(
                        f"Backup is missing required Stream Memory tables: {sorted(missing)}"
                    )
                ver_row = verify_conn.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;"
                ).fetchone()
                ver_num = int(ver_row[0]) if ver_row else 0
                if ver_num < 1 or ver_num > SCHEMA_VERSION:
                    raise DatabaseCorruptionError(
                        f"Backup schema version {ver_num} incompatible with supported v{SCHEMA_VERSION}"
                    )
            finally:
                verify_conn.close()

            # Step 3: Atomic replace of target DB + clean removal of stale WAL/SHM sidecars
            os.replace(temp_target, target_db_path)
            set_private_file_permissions(target_db_path)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{target_db_path}{suffix}")
                if sidecar.exists() and not sidecar.is_symlink():
                    sidecar.unlink()
        except BaseException:
            if temp_target.exists():
                temp_target.unlink()
            raise

    verified_db = Database(target_db_path)
    try:
        counts = verified_db.table_counts()
        ver = verified_db.schema_version()
    finally:
        verified_db.close()

    return {
        "restored_from": str(backup_db_path),
        "target_db": str(target_db_path),
        "sha256": actual_sha256,
        "schema_version": ver,
        "table_counts": counts,
    }
