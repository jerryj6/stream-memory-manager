"""Persistence, WAL durability, corruption detection, online backup/restore, and filesystem permission tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from stream_memory_manager.db import Database, restore_backup
from stream_memory_manager.models import (
    DatabaseCorruptionError,
    InclusionDecision,
    MemoryRecordInput,
    StreamMemoryError,
)
from stream_memory_manager.registry import KnowledgeRegistry


def test_db_reopen_permissions_and_wal_mode(tmp_path: Path) -> None:
    db_path = tmp_path / "secure_data" / "stream_memory.db"
    db = Database(db_path)
    try:
        reg = KnowledgeRegistry(db)
        reg.upsert_record(
            MemoryRecordInput(
                logical_id="persist_1",
                title="Durable Record",
                category="CORE",
                body="Persisted cleanly in WAL + FULL sync mode.",
                inclusion_decision=InclusionDecision.APPROVED,
            )
        )
        mode = str(db.conn.execute("PRAGMA journal_mode;").fetchone()[0]).lower()
        assert mode == "wal"
        assert (os.stat(db_path).st_mode & 0o777) == 0o600
        assert (os.stat(db_path.parent).st_mode & 0o777) == 0o700
    finally:
        db.close()

    # Reopen and confirm durability
    db2 = Database(db_path)
    try:
        rec = KnowledgeRegistry(db2).get_record("persist_1")
        assert rec is not None
        assert rec["title"] == "Durable Record"
    finally:
        db2.close()


def test_corrupted_database_fails_closed_and_is_never_recreated(tmp_path: Path) -> None:
    """Section 25.6: Never replace a corrupted DB with an empty one!"""
    bad_db = tmp_path / "corrupt.db"
    bad_db.write_bytes(b"NOT_A_VALID_SQLITE_FILE_CORRUPT_HEADER_DATA_1234567890")
    original_bytes = bad_db.read_bytes()

    with pytest.raises(DatabaseCorruptionError):
        Database(bad_db)

    # Corrupt file must remain untouched (not silently replaced!)
    assert bad_db.read_bytes() == original_bytes


def test_online_backup_restore_and_checksum_tamper_detection(tmp_path: Path) -> None:
    db_path = tmp_path / "live" / "stream_memory.db"
    backup_dir = tmp_path / "backups"
    db = Database(db_path)
    try:
        reg = KnowledgeRegistry(db)
        reg.upsert_record(
            MemoryRecordInput(
                logical_id="bak_rec",
                title="Backed Up Record",
                category="CORE",
                body="Must survive full restore.",
                inclusion_decision=InclusionDecision.APPROVED,
            )
        )
        bak_res = db.backup_to(backup_dir, label="pre_import")
    finally:
        db.close()

    backup_file = Path(bak_res["backup_path"])
    assert backup_file.exists()
    assert (os.stat(backup_file).st_mode & 0o777) == 0o600

    # Restore to fresh target path
    restored_path = tmp_path / "restored" / "stream_memory.db"
    res = restore_backup(backup_file, restored_path)
    assert res["table_counts"]["memory_records"] == 1
    db_check = Database(restored_path)
    try:
        assert KnowledgeRegistry(db_check).get_record("bak_rec") is not None
    finally:
        db_check.close()

    # Tamper with backup file -> restore MUST reject SHA-256 mismatch!
    raw = bytearray(backup_file.read_bytes())
    raw[-1] ^= 0xFF
    backup_file.write_bytes(bytes(raw))
    with pytest.raises(DatabaseCorruptionError, match="SHA-256 mismatch"):
        restore_backup(backup_file, tmp_path / "tampered_target.db")


def test_read_only_database_blocks_writes(tmp_path: Path) -> None:
    db_path = tmp_path / "ro.db"
    db = Database(db_path)
    db.close()

    ro_db = Database(db_path, read_only=True)
    try:
        with pytest.raises(StreamMemoryError, match="read-only"), ro_db.transaction():
            pass
    finally:
        ro_db.close()
