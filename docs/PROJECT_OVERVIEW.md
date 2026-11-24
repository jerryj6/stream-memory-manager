# Project Overview & Requirements

## 1. Mission
**Stream Memory Manager** is a maintained, local-first personal knowledge management (PKM) system and fail-closed official **Sandbar Stream MCP** integration. It transforms heterogeneous personal and technical context exports into a coherent, provenance-tracked canonical knowledge base, compiles approved records into concise, independently retrievable Sandbar Stream Logs inside a single dedicated `Memory` folder, and governs every remote operation with strict approval, rate-limiting, verification, and crash-recovery invariants.

## 2. Priority Hierarchy
When architectural or operational objectives conflict, the system strictly favors higher-priority objectives:

| Priority | Objective | Concrete Manifestation |
| :---: | :--- | :--- |
| **1** | Protect existing user data | Never overwrite unrelated user Logs, folders, folder instructions, or user briefings; fail closed on `expected_last_update_ts` conflicts or duplicate `Memory` folders. |
| **2** | Prevent unauthorized remote changes | OAuth login never implies write approval; immutable `plan_id` approval required; strict `--mode` to endpoint isolation. |
| **3** | Prevent duplicate writes & flooding | Single-writer OS `flock`, conservative >= 2.0s account-level pacing, hard request budgets, zero blind retry on uncertain writes. |
| **4** | Preserve information accurately | Immutable content-addressed revisions, semantic splitting with zero dropped tokens, temporal/evidence-based supersession. |
| **5** | Maintain recoverability | WAL SQLite journal persisted before network dispatch, crash recovery at every boundary, checksum-verified online backups. |
| **6** | Respect privacy & inclusion decisions | Hard-blocked sensitive/secret classes, review-required holds, owner-local gitignored rules, zero personal data in tracked repo. |
| **7** | Maximize conversational retrieval utility | Self-contained `<= 900`-word Logs, descriptive category-prefixed titles, dynamic `CORE — Knowledge Index`, honest local vs native evaluation. |
| **8** | Maintain understandable local state | Single SQLite database + open Markdown/JSON exports with SHA-256 manifests and zero platform lock-in. |
| **9** | Make the system intuitive for future agents | Compact `status --json`, `doctor --json`, deterministic exit codes, accretive `AGENTS.md` + `docs/`. |
| **10** | Minimize unnecessary complexity | Cohesive Python 3.12 package using standard SQLite, Pydantic, Typer, and official `mcp` SDK; zero background daemons or external DBs. |

## 3. Functional Requirements Summary
1. **Local-Only Full Usability:** Ingestion, reconciliation, privacy review, compilation, dry-run planning, open-format export, local BM25 evaluation, backup/restore, and full mock-server testing execute without any Sandbar account connection.
2. **Single User-Facing Folder (`Memory`):** All imported memory Logs target exactly one flat folder named `Memory` (Sandbar Stream does not support nested folders). Semantic grouping lives inside titles (`CATEGORY — Specific Subject`), metadata headers, and the generated `CORE — Knowledge Index` Log.
3. **Official Protocol Exclusivity:** Connects strictly to `https://api.sandbar.com/mcp` (live mode) or loopback mock servers (mock mode) using official OAuth 2.1 + PKCE S256 and MCP Streamable HTTP. Zero undocumented private endpoints, browser scraping, or token extraction.
4. **Honest Representation of Limitations:** Because official Sandbar MCP exposes no deletion tool and (in baseline docs) no Log-body edit tool, updates and removals degrade honestly to `MANUAL_REPLACEMENT_REQUIRED` / `MANUAL_DELETION_REQUIRED` unless live `tools/list` confirms a write-update capability.
5. **Continuous Maintainability:** Supports future incremental context imports, revision diffs, remote drift detection, and non-destructive reconciliation over time.
