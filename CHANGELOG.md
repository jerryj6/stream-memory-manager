# Changelog

All notable changes to **Stream Memory Manager** are documented in this file.

## [0.2.0] — 2026-11-25

### Added
- **Stream Memory Studio (Unified 4-Tab Local Web App):** Running `stream-memory` (or `uvx --from git+https://github.com/jerryj6/stream-memory-manager stream-memory`) launches a clean 4-tab Studio (`Collect -> Consolidate -> Briefing & Preview -> Live Sync & Monitor`) directly at `http://127.0.0.1:4319/view` — zero 13-command terminal gauntlet.
- **Semantic Consolidation & Hygiene Engine (`consolidator.py`, `consolidate`, `merge`):** Detects overlapping records via TF-IDF + entity overlap, flags sparse fragments / repeated meta-boilerplate / dated windows, merges topics cleanly into dense 650–900 word Topic Dossiers, and supports opt-in BYOK / local Ollama Auto-Merge.
- **Live Sync Monitor, SSE Progress & Live Search Tester (`inspect-live`, `search-live`):** Pulls live `Memory` & `Memory Archive` state via official Sandbar MCP, streams real-time SSE sync/quarantine progress in the Studio, tests live Stream retrieval quality right in the UI, and links directly to `https://stream.sandbar.com`.
- **1-Click Safe Quarantine & Reset (`reset-memory`, `quarantine_logs_to_archive`):** Preserves exact float `lastUpdateUnixTs` for Sandbar `set_note_folder` optimistic concurrency so stale or all `Memory` notes can be quarantined into `Memory Archive` via 100% official MCP for clean deletion in Stream Web.
- **Deep Local Git Repo Harvester (`local_projects`):** Scans local git workspaces read-only for `README.md` summaries and tech stacks while skipping secrets/`.env`.

### Changed
- **Voice-Friendly Natural Stream Notes & Briefing:** Strips robotic `[Confirmed]`/`[Constraint]`/`Date/Period:` clutter from compiled Stream Notes and packs a high-signal Always-On Stream Briefing with 1-click Copy + paste guide.
- **Lean, Auditable Repository:** Streamlined 26 sprawling docs into 3 focused technical references (`docs/ARCHITECTURE.md`, `docs/SANDBAR_MCP.md`, `docs/SECURITY_AND_RECOVERY.md`) and updated `SKILL.md` for `npx skills add` + `uvx`.

## [0.1.0] — 2026-11-24

- Initial open-source release with local agent harvesters, premade Max-Thinking `STREAM_MEMORY_EXPORT v1` web prompt kit, privacy engine, 18-state crash-safe operation journal, OAuth 2.1 + PKCE, and live-verified Sandbar Stream MCP block-array support.
