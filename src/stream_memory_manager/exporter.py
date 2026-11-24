"""Open-format exporters strictly separating local-complete archives from Stream-ready privacy-filtered exports."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from stream_memory_manager.compiler import export_manifest_json, load_compiled_artifacts
from stream_memory_manager.models import (
    ErrorClass,
    ExitCode,
    PrivacyViolationError,
    StreamMemoryError,
    utc_now_iso,
)
from stream_memory_manager.privacy import assert_payload_safe, assert_record_exportable
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.security import (
    atomic_write_private_text,
    ensure_private_dir,
    safe_resolve_under,
)


def _safe_filename(title: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", title).strip("_")
    return (slug[:80] or "record") + ".md"


def export_bundle(
    registry: KnowledgeRegistry,
    output_dir: Path,
    *,
    scope: str = "stream-ready",
) -> dict[str, Any]:
    """Export open-format artifacts using atomic 0600 writes and symlink/traversal guards.

    - `stream-ready`: ONLY approved, revision-current, privacy-verified compiled Logs + manifest +
      filtered provenance (only sources referenced by exported records).
    - `local-complete`: Full local canonical registry snapshot for owner archival only.
    """
    if scope not in ("stream-ready", "local-complete"):
        raise StreamMemoryError(
            f"Unsupported export scope {scope!r}; choose 'stream-ready' or 'local-complete'.",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    out_root = ensure_private_dir(output_dir.resolve())
    created_files: list[str] = []

    if scope == "stream-ready":
        artifacts = load_compiled_artifacts(registry)
        if not artifacts:
            raise StreamMemoryError(
                "No compiled artifacts to export. Run `stream-memory compile` first.",
                error_class=ErrorClass.VALIDATION_PERMANENT,
                exit_code=ExitCode.VALIDATION_ERROR,
            )

        # Re-verify Invariant 10 on every artifact AND check revision freshness (Audit R13)
        referenced_source_ids: set[str] = set()
        for art in artifacts:
            assert_payload_safe(art.title, art.body, label=art.artifact_key)
            if art.artifact_kind == "log" and art.logical_id != "core_knowledge_index":
                rec = registry.get_record(art.logical_id)
                if rec is None:
                    raise PrivacyViolationError(
                        f"Compiled artifact {art.artifact_key} references missing canonical record {art.logical_id!r}."
                    )
                if int(rec["current_revision"]) != art.revision_number:
                    raise PrivacyViolationError(
                        f"Compiled artifact {art.artifact_key} is stale (rev {art.revision_number} != current rev {rec['current_revision']}); recompile first."
                    )
                assert_record_exportable(rec)
                for ref in rec.get("source_refs") or []:
                    referenced_source_ids.add(str(ref).split("#", 1)[0])

        logs_dir = ensure_private_dir(safe_resolve_under(out_root, "logs"))
        consolidated_parts: list[str] = [
            f"# Stream Memory Manager — Stream-Ready Export ({utc_now_iso()})",
            "",
            "Privacy-filtered, approved compiled Logs only.",
            "",
        ]
        for idx, art in enumerate(artifacts, start=1):
            if art.artifact_kind != "log":
                continue
            fname = f"{idx:03d}_{_safe_filename(art.title)}"
            fpath = safe_resolve_under(logs_dir, fname)
            atomic_write_private_text(fpath, f"# {art.title}\n\n{art.body}\n")
            created_files.append(str(fpath))
            consolidated_parts.append(f"# {art.title}\n\n{art.body}\n\n---\n")

        cons_path = safe_resolve_under(out_root, "consolidated_stream_ready.md")
        atomic_write_private_text(cons_path, "\n".join(consolidated_parts))
        created_files.append(str(cons_path))

        manifest_path = safe_resolve_under(out_root, "manifest.json")
        atomic_write_private_text(manifest_path, export_manifest_json(artifacts))
        created_files.append(str(manifest_path))

        json_path = safe_resolve_under(out_root, "stream_ready_records.json")
        atomic_write_private_text(
            json_path,
            json.dumps(
                {
                    "scope": "stream-ready",
                    "exported_at": utc_now_iso(),
                    "artifacts": [a.model_dump() for a in artifacts],
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            ),
        )
        created_files.append(str(json_path))

        # Sanitized provenance: strictly filter sources to those referenced by exported records!
        prov = {
            "scope": "sanitized-provenance",
            "exported_at": utc_now_iso(),
            "sources": [
                {
                    "source_id": s["source_id"],
                    "source_label": s["source_label"],
                    "source_format": s["source_format"],
                    "content_sha256": s["content_sha256"],
                    "ingested_at": s["ingested_at"],
                }
                for s in registry.list_sources()
                if str(s["source_id"]) in referenced_source_ids
            ],
            "approved_logical_ids": sorted(
                {a.logical_id for a in artifacts if a.artifact_kind == "log"}
            ),
        }
        prov_path = safe_resolve_under(out_root, "sanitized_provenance.json")
        atomic_write_private_text(prov_path, json.dumps(prov, indent=2, sort_keys=True))
        created_files.append(str(prov_path))

        return {
            "scope": scope,
            "output_dir": str(out_root),
            "files_written": len(created_files),
            "log_count": sum(1 for a in artifacts if a.artifact_kind == "log"),
            "manifest_path": str(manifest_path),
            "consolidated_path": str(cons_path),
        }

    # local-complete export (owner archival only)
    all_records = registry.list_records()
    full_payload = {
        "scope": "local-complete",
        "warning": "OWNER LOCAL ARCHIVE ONLY — contains historical, unapproved, or excluded records. Do NOT upload directly.",
        "exported_at": utc_now_iso(),
        "sources": registry.list_sources(),
        "records": all_records,
        "issues": registry.list_issues(status=None),
    }
    full_json = safe_resolve_under(out_root, "local_complete_registry.json")
    atomic_write_private_text(
        full_json, json.dumps(full_payload, indent=2, sort_keys=True, ensure_ascii=False)
    )
    created_files.append(str(full_json))

    md_lines = [
        f"# Stream Memory Manager — Local Complete Registry ({utc_now_iso()})",
        "",
        "> WARNING: Owner local archive only. Includes historical/unapproved/excluded records.",
        "",
    ]
    for rec in all_records:
        md_lines.append(
            f"# [{rec['logical_id']}] {rec['title']}\n\n"
            f"- Status: {rec['status']} | Inclusion: {rec['inclusion_decision']} | Privacy: {rec['privacy_classification']}\n\n"
            f"{rec['body']}\n\n---\n"
        )
    full_md = safe_resolve_under(out_root, "local_complete_registry.md")
    atomic_write_private_text(full_md, "\n".join(md_lines))
    created_files.append(str(full_md))

    return {
        "scope": scope,
        "output_dir": str(out_root),
        "files_written": len(created_files),
        "record_count": len(all_records),
        "json_path": str(full_json),
        "markdown_path": str(full_md),
    }
