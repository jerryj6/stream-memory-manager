"""Canonical Personal Knowledge Registry backed by durable SQLite."""

from __future__ import annotations

import json
import uuid
from typing import Any

from stream_memory_manager.db import Database
from stream_memory_manager.models import (
    ErrorClass,
    EvidenceClass,
    ExitCode,
    InclusionDecision,
    MemoryRecordInput,
    PrivacyClassification,
    RecordStatus,
    RelationType,
    RemoteSyncStatus,
    StreamMemoryError,
    utc_now_iso,
)
from stream_memory_manager.security import canonical_json_hash, sha256_text


def compute_revision_checksum(
    *,
    title: str,
    body: str,
    effective_date: str | None,
    observed_date: str | None,
    last_confirmed_date: str | None,
    evidence_class: str,
    search_aliases: list[str],
) -> str:
    return canonical_json_hash(
        {
            "title": title.strip(),
            "body": body.replace("\r\n", "\n").replace("\r", "\n").strip(),
            "effective_date": effective_date,
            "observed_date": observed_date,
            "last_confirmed_date": last_confirmed_date,
            "evidence_class": evidence_class,
            "search_aliases": sorted({a.strip() for a in search_aliases if a.strip()}),
        }
    )


class KnowledgeRegistry:
    """Authoritative local personal knowledge base independent of Sandbar."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def register_source(
        self,
        *,
        source_path: str,
        source_label: str,
        source_format: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        content_sha = sha256_text(content)
        existing = self.db.conn.execute(
            "SELECT source_id FROM sources WHERE source_path = ? AND content_sha256 = ?;",
            (source_path, content_sha),
        ).fetchone()
        if existing:
            return str(existing["source_id"])

        source_id = f"src_{content_sha[:16]}"
        # Handle same hash at different path cleanly
        by_id = self.db.conn.execute(
            "SELECT source_id FROM sources WHERE source_id = ?;", (source_id,)
        ).fetchone()
        if by_id:
            source_id = f"src_{sha256_text(source_path + ':' + content_sha)[:16]}"

        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO sources (
                    source_id, source_path, source_label, source_format,
                    content_sha256, byte_size, trust_level, ingested_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, 'UNTRUSTED_DATA', ?, ?);
                """,
                (
                    source_id,
                    source_path,
                    source_label,
                    source_format,
                    content_sha,
                    len(content.encode("utf-8")),
                    utc_now_iso(),
                    json.dumps(metadata or {}, sort_keys=True),
                ),
            )
        return source_id

    def upsert_record(self, rec: MemoryRecordInput) -> dict[str, Any]:
        """Insert a new canonical logical record or append an immutable revision if changed.

        Invariant 3: `logical_id` remains stable across title and body changes.
        Re-ingesting identical normalized content is a no-op (no spurious revisions).
        """
        now = utc_now_iso()
        clean_title = rec.title.strip()
        clean_body = rec.body.replace("\r\n", "\n").replace("\r", "\n").strip()
        aliases = sorted({a.strip() for a in rec.search_aliases if a.strip()})
        checksum = compute_revision_checksum(
            title=clean_title,
            body=clean_body,
            effective_date=rec.effective_date,
            observed_date=rec.observed_date,
            last_confirmed_date=rec.last_confirmed_date,
            evidence_class=rec.evidence_class.value,
            search_aliases=aliases,
        )

        with self.db.transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM memory_records WHERE logical_id = ?;", (rec.logical_id,)
            ).fetchone()

            if existing is None:
                rev_num = 1
                rev_id = f"{rec.logical_id}@r{rev_num}"
                conn.execute(
                    """
                    INSERT INTO memory_records (
                        logical_id, current_revision, title, category, logical_group,
                        canonical_subject, status, privacy_classification, inclusion_decision,
                        destination_eligible, sync_status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        rec.logical_id,
                        rev_num,
                        clean_title,
                        rec.category.strip(),
                        rec.logical_group.strip(),
                        (rec.canonical_subject or clean_title).strip(),
                        rec.status.value,
                        rec.privacy_classification.value,
                        rec.inclusion_decision.value,
                        1 if rec.destination_eligible else 0,
                        RemoteSyncStatus.UNSYNCED.value,
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO record_revisions (
                        revision_id, logical_id, revision_number, title, body,
                        content_checksum, effective_date, observed_date, last_confirmed_date,
                        evidence_class, search_aliases_json, update_triggers,
                        source_refs_json, source_hashes_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        rev_id,
                        rec.logical_id,
                        rev_num,
                        clean_title,
                        clean_body,
                        checksum,
                        rec.effective_date,
                        rec.observed_date,
                        rec.last_confirmed_date,
                        rec.evidence_class.value,
                        json.dumps(aliases),
                        rec.update_triggers,
                        json.dumps(rec.source_refs),
                        json.dumps(rec.source_hashes),
                        now,
                    ),
                )
                self._insert_claims(conn, rec.logical_id, rev_num, rec.claims, now)
                return {
                    "logical_id": rec.logical_id,
                    "revision_number": rev_num,
                    "action": "created",
                    "checksum": checksum,
                }

            current_rev = int(existing["current_revision"])
            latest_rev_row = conn.execute(
                """
                SELECT * FROM record_revisions
                WHERE logical_id = ? AND revision_number = ?;
                """,
                (rec.logical_id, current_rev),
            ).fetchone()

            if latest_rev_row and str(latest_rev_row["content_checksum"]) == checksum:
                # Merge provenance source refs/hashes without bumping revision number
                existing_refs = json.loads(str(latest_rev_row["source_refs_json"]))
                existing_hashes = json.loads(str(latest_rev_row["source_hashes_json"]))
                merged_refs = sorted(set(existing_refs) | set(rec.source_refs))
                merged_hashes = sorted(set(existing_hashes) | set(rec.source_hashes))
                if merged_refs != existing_refs or merged_hashes != existing_hashes:
                    conn.execute(
                        """
                        UPDATE record_revisions
                        SET source_refs_json = ?, source_hashes_json = ?
                        WHERE revision_id = ?;
                        """,
                        (
                            json.dumps(merged_refs),
                            json.dumps(merged_hashes),
                            str(latest_rev_row["revision_id"]),
                        ),
                    )
                return {
                    "logical_id": rec.logical_id,
                    "revision_number": current_rev,
                    "action": "unchanged",
                    "checksum": checksum,
                }

            new_rev = current_rev + 1
            new_rev_id = f"{rec.logical_id}@r{new_rev}"
            old_rev_id = f"{rec.logical_id}@r{current_rev}"
            conn.execute(
                """
                INSERT INTO record_revisions (
                    revision_id, logical_id, revision_number, title, body,
                    content_checksum, effective_date, observed_date, last_confirmed_date,
                    evidence_class, search_aliases_json, update_triggers,
                    source_refs_json, source_hashes_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    new_rev_id,
                    rec.logical_id,
                    new_rev,
                    clean_title,
                    clean_body,
                    checksum,
                    rec.effective_date,
                    rec.observed_date,
                    rec.last_confirmed_date,
                    rec.evidence_class.value,
                    json.dumps(aliases),
                    rec.update_triggers,
                    json.dumps(rec.source_refs),
                    json.dumps(rec.source_hashes),
                    now,
                ),
            )
            conn.execute(
                "UPDATE record_revisions SET superseded_by_revision_id = ? WHERE revision_id = ?;",
                (new_rev_id, old_rev_id),
            )
            # If already verified remotely, mark as needing remote update reconciliation
            prior_sync = str(existing["sync_status"])
            next_sync = (
                RemoteSyncStatus.NEEDS_MANUAL_UPDATE.value
                if prior_sync == RemoteSyncStatus.VERIFIED.value
                else prior_sync
            )
            # Security fix (Audit R12): Whenever content changes on an existing logical_id,
            # ALWAYS reset/update privacy_classification, inclusion_decision, and destination_eligible
            # from the new revision's scan so untrusted overwrites NEVER inherit prior APPROVED status!
            conn.execute(
                """
                UPDATE memory_records
                SET current_revision = ?, title = ?, category = ?, logical_group = ?,
                    canonical_subject = ?, status = ?, privacy_classification = ?,
                    inclusion_decision = ?, destination_eligible = ?, sync_status = ?, updated_at = ?
                WHERE logical_id = ?;
                """,
                (
                    new_rev,
                    clean_title,
                    rec.category.strip(),
                    rec.logical_group.strip(),
                    (rec.canonical_subject or clean_title).strip(),
                    rec.status.value,
                    rec.privacy_classification.value,
                    rec.inclusion_decision.value,
                    1 if rec.destination_eligible else 0,
                    next_sync,
                    now,
                    rec.logical_id,
                ),
            )
            self._insert_claims(conn, rec.logical_id, new_rev, rec.claims, now)
            return {
                "logical_id": rec.logical_id,
                "revision_number": new_rev,
                "action": "revised",
                "checksum": checksum,
            }

    def _insert_claims(
        self,
        conn: Any,
        logical_id: str,
        rev_num: int,
        claims: list[dict[str, Any]],
        now: str,
    ) -> None:
        for idx, claim in enumerate(claims, start=1):
            text = str(claim.get("claim_text", "")).strip()
            if not text:
                continue
            ev = str(claim.get("evidence_class", EvidenceClass.USER_CONFIRMED.value))
            claim_id = f"{logical_id}@r{rev_num}:c{idx}"
            conn.execute(
                """
                INSERT OR REPLACE INTO record_claims (
                    claim_id, logical_id, revision_number, claim_text,
                    evidence_class, effective_date, observed_date, source_ref, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    claim_id,
                    logical_id,
                    rev_num,
                    text,
                    ev,
                    claim.get("effective_date"),
                    claim.get("observed_date"),
                    claim.get("source_ref"),
                    str(claim.get("status", "ACTIVE")),
                    now,
                ),
            )

    def add_relationship(
        self,
        source_logical_id: str,
        target_logical_id: str,
        relation_type: RelationType,
        note: str = "",
    ) -> None:
        if source_logical_id == target_logical_id:
            return
        with self.db.transaction() as conn:
            src_exists = conn.execute(
                "SELECT 1 FROM memory_records WHERE logical_id = ?;", (source_logical_id,)
            ).fetchone()
            tgt_exists = conn.execute(
                "SELECT 1 FROM memory_records WHERE logical_id = ?;", (target_logical_id,)
            ).fetchone()
            if not src_exists or not tgt_exists:
                return
            conn.execute(
                """
                INSERT OR IGNORE INTO record_relationships (
                    source_logical_id, target_logical_id, relation_type, note, created_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (source_logical_id, target_logical_id, relation_type.value, note, utc_now_iso()),
            )

    def set_decision(
        self,
        logical_id: str,
        *,
        inclusion_decision: InclusionDecision | None = None,
        privacy_classification: PrivacyClassification | None = None,
        status: RecordStatus | None = None,
        destination_eligible: bool | None = None,
    ) -> dict[str, Any]:
        row = self.get_record(logical_id)
        if row is None:
            raise StreamMemoryError(
                f"Record not found: {logical_id}",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        inc = inclusion_decision.value if inclusion_decision else row["inclusion_decision"]
        priv = (
            privacy_classification.value
            if privacy_classification
            else row["privacy_classification"]
        )
        st = status.value if status else row["status"]
        elig = (
            (1 if destination_eligible else 0)
            if destination_eligible is not None
            else int(row["destination_eligible"])
        )
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE memory_records
                SET inclusion_decision = ?, privacy_classification = ?, status = ?,
                    destination_eligible = ?, updated_at = ?
                WHERE logical_id = ?;
                """,
                (inc, priv, st, elig, utc_now_iso(), logical_id),
            )
        updated = self.get_record(logical_id)
        assert updated is not None
        return updated

    def mark_superseded(
        self,
        old_logical_id: str,
        new_logical_id: str,
        *,
        reason: str = "",
    ) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE memory_records
                SET status = ?, destination_eligible = 0, updated_at = ?
                WHERE logical_id = ?;
                """,
                (RecordStatus.SUPERSEDED.value, utc_now_iso(), old_logical_id),
            )
        self.add_relationship(new_logical_id, old_logical_id, RelationType.SUPERSEDES, note=reason)

    def mark_remote_verified(
        self,
        logical_id: str,
        *,
        remote_id: str,
        remote_folder_id: str | None,
        remote_last_update_ts: int | None,
    ) -> None:
        now = utc_now_iso()
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE memory_records
                SET sync_status = ?, remote_id = ?, remote_folder_id = ?,
                    remote_last_update_ts = ?, verified_at = ?, updated_at = ?
                WHERE logical_id = ?;
                """,
                (
                    RemoteSyncStatus.VERIFIED.value,
                    remote_id,
                    remote_folder_id,
                    remote_last_update_ts,
                    now,
                    now,
                    logical_id,
                ),
            )

    def mark_sync_status(self, logical_id: str, status: RemoteSyncStatus) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE memory_records SET sync_status = ?, updated_at = ? WHERE logical_id = ?;",
                (status.value, utc_now_iso(), logical_id),
            )

    def record_issue(
        self,
        *,
        issue_type: str,
        severity: str,
        summary: str,
        logical_id: str | None = None,
        related_logical_id: str | None = None,
        details: dict[str, Any] | None = None,
        issue_id: str | None = None,
    ) -> str:
        iid = issue_id or f"iss_{uuid.uuid4().hex[:12]}"
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO reconciliation_issues (
                    issue_id, issue_type, severity, logical_id, related_logical_id,
                    summary, details_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN', ?);
                """,
                (
                    iid,
                    issue_type,
                    severity,
                    logical_id,
                    related_logical_id,
                    summary,
                    json.dumps(details or {}, sort_keys=True),
                    utc_now_iso(),
                ),
            )
        return iid

    def resolve_issue(self, issue_id: str, note: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE reconciliation_issues
                SET status = 'RESOLVED', resolution_note = ?, resolved_at = ?
                WHERE issue_id = ?;
                """,
                (note, utc_now_iso(), issue_id),
            )

    def list_issues(self, *, status: str | None = "OPEN") -> list[dict[str, Any]]:
        if status is None:
            rows = self.db.conn.execute(
                "SELECT * FROM reconciliation_issues ORDER BY severity DESC, created_at ASC;"
            ).fetchall()
        else:
            rows = self.db.conn.execute(
                "SELECT * FROM reconciliation_issues WHERE status = ? ORDER BY severity DESC, created_at ASC;",
                (status,),
            ).fetchall()
        return [
            {
                **dict(r),
                "details": json.loads(str(r["details_json"])),
            }
            for r in rows
        ]

    def get_record(self, logical_id: str) -> dict[str, Any] | None:
        row = self.db.conn.execute(
            """
            SELECT m.*, r.revision_id, r.body, r.content_checksum, r.effective_date,
                   r.observed_date, r.last_confirmed_date, r.evidence_class,
                   r.search_aliases_json, r.update_triggers, r.source_refs_json,
                   r.source_hashes_json
            FROM memory_records m
            JOIN record_revisions r
              ON r.logical_id = m.logical_id AND r.revision_number = m.current_revision
            WHERE m.logical_id = ?;
            """,
            (logical_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["search_aliases"] = json.loads(str(d.pop("search_aliases_json")))
        d["source_refs"] = json.loads(str(d.pop("source_refs_json")))
        d["source_hashes"] = json.loads(str(d.pop("source_hashes_json")))
        d["destination_eligible"] = bool(d["destination_eligible"])
        d["claims"] = [
            dict(c)
            for c in self.db.conn.execute(
                "SELECT * FROM record_claims WHERE logical_id = ? AND revision_number = ? ORDER BY claim_id;",
                (logical_id, d["current_revision"]),
            ).fetchall()
        ]
        d["relationships"] = [
            dict(rel)
            for rel in self.db.conn.execute(
                """
                SELECT * FROM record_relationships
                WHERE source_logical_id = ? OR target_logical_id = ?
                ORDER BY id;
                """,
                (logical_id, logical_id),
            ).fetchall()
        ]
        return d

    def list_revisions(self, logical_id: str) -> list[dict[str, Any]]:
        rows = self.db.conn.execute(
            "SELECT * FROM record_revisions WHERE logical_id = ? ORDER BY revision_number ASC;",
            (logical_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_records(
        self,
        *,
        category: str | None = None,
        status: str | None = None,
        inclusion_decision: str | None = None,
        only_destination_eligible: bool = False,
    ) -> list[dict[str, Any]]:
        rows = self.db.conn.execute(
            """
            SELECT m.*, r.revision_id, r.body, r.content_checksum, r.effective_date,
                   r.observed_date, r.last_confirmed_date, r.evidence_class,
                   r.search_aliases_json, r.update_triggers, r.source_refs_json,
                   r.source_hashes_json
            FROM memory_records m
            JOIN record_revisions r
              ON r.logical_id = m.logical_id AND r.revision_number = m.current_revision
            WHERE (? IS NULL OR m.category = ?)
              AND (? IS NULL OR m.status = ?)
              AND (? IS NULL OR m.inclusion_decision = ?)
              AND (? = 0 OR m.destination_eligible = 1)
            ORDER BY m.logical_id ASC;
            """,
            (
                category,
                category,
                status,
                status,
                inclusion_decision,
                inclusion_decision,
                1 if only_destination_eligible else 0,
            ),
        ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            d = dict(row)
            d["search_aliases"] = json.loads(str(d.pop("search_aliases_json")))
            d["source_refs"] = json.loads(str(d.pop("source_refs_json")))
            d["source_hashes"] = json.loads(str(d.pop("source_hashes_json")))
            d["destination_eligible"] = bool(d["destination_eligible"])
            results.append(d)
        return results

    def list_sources(self) -> list[dict[str, Any]]:
        rows = self.db.conn.execute("SELECT * FROM sources ORDER BY ingested_at ASC;").fetchall()
        return [{**dict(r), "metadata": json.loads(str(r["metadata_json"]))} for r in rows]
