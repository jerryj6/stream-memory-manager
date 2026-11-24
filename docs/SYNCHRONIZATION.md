# Incremental Synchronization & Drift Management

Stream Memory Manager is designed as a long-term maintained personal knowledge base, not a one-off upload script.

## 1. Stable Identity Across Revisions
Every canonical knowledge record is keyed by a durable `logical_id` (e.g., `tech_t02`, `v2_01_01`, or a slugged user ID). Editing a record's title or body appends a new immutable row to `record_revisions` (`revision_number + 1`), links `superseded_by_revision_id`, preserves the original `logical_id`, and resets `inclusion_decision` on untrusted re-ingestion so changed content must be re-reviewed before export.

## 2. Capability-Aware Change Planning (`planner.py`)
When `plan --mode live` observes the current `Memory` folder and compares compiled local artifacts against verified remote state (account-scoped by `account_binding_hash`):

| Local vs Remote Condition | Server Supports `update_log` = `False` (Baseline Docs) | Server Supports `update_log` = `True` (If Confirmed Live) |
| :--- | :--- | :--- |
| **Artifact unchanged** (normalized hash matches remote Log) | Skipped cleanly (`skipped_unchanged`) | Skipped cleanly (`skipped_unchanged`) |
| **New local Log** (no remote match) | `CREATE_LOG` | `CREATE_LOG` |
| **Local revision changed** (remote Log exists with old hash) | Emits `MANUAL_REPLACEMENT_REQUIRED` (honest non-destructive manual notice) | Plans `UPDATE_LOG` with `expected_last_update_ts` optimistic concurrency token |
| **Remote Log edited manually by user** (`lastUpdateUnixTs` diverged) | Never overwrites; flags conflict | Server rejects stale `expected_last_update_ts` -> transitions to `CONFLICTED` (user edit preserved!) |
| **Local record excluded / deleted / split shrunk from N parts to M** | Emits `MANUAL_DELETION_REQUIRED` referencing exact remote `id` + title | Emits `MANUAL_DELETION_REQUIRED` (no delete tool in official MCP) |
| **Live `Memory` folder emptied manually by user** (`is_offline_assumption=False`, `existing_memory_logs=[]`) | Plans fresh `CREATE_LOG`s (does not assume stale local sync status still exists remotely) | Plans fresh `CREATE_LOG`s |

## 3. Ongoing Context Maintenance Workflow
1. Add or update Markdown/JSON exports locally and run `stream-memory ingest <file>`.
2. Run `stream-memory conflicts --json` and `stream-memory privacy-review --json` to resolve any temporal supersessions, contradictions, or privacy flags.
3. Run `stream-memory compile --json` and `stream-memory diff --json` to inspect exact changes.
4. Generate a bounded plan (`plan --mode live`), review `preview`, approve the exact `plan_id`, and apply.
5. Complete any listed `MANUAL_DELETION_REQUIRED` or `MANUAL_REPLACEMENT_REQUIRED` cleanups directly inside the Sandbar Stream app.
