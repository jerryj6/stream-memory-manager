# Project Status Snapshot

**Last Updated:** `2026-11-24T07:47:00Z`  
**Repository Layout:** Local-first universal Python 3.12 agent skill + harvester + ephemeral local UI + Sandbar Stream MCP pusher (`SKILL.md`, `src/`, `tests/`, `docs/`, gitignored `data/`)  
**Live Production Validation:** **COMPLETE & VERIFIED** (End-to-end OAuth 2.1 + silent refresh + 1-Log canary + full multi-batch live push verified against `https://api.sandbar.com/mcp` with `0` duplicates, `0` errors, and active live semantic search)

## 1. Phase Completion Tracker (Phases A–J)

| Phase | Description | Status | Verified Evidence |
| :---: | :--- | :---: | :--- |
| **A** | Official Sandbar MCP Research, Live Unauthenticated OAuth Discovery & Environment Audit | **COMPLETE** | Live docs (`2026-11-20`), KB (`2026-11-08`), RFC 9728/8414 verified (`docs/SANDBAR_CAPABILITIES.md`) |
| **B** | Architecture, Universal Harvesters, Utility Scoring, Ephemeral `/view` Staging UI & Core Implementation | **COMPLETE** | 26 Python modules under `src/stream_memory_manager/`, `mypy --strict` 0 errors, `SKILL.md` + premade max-thinking `STREAM_MEMORY_EXPORT v1` prompt kit |
| **C** | Stateful Localhost Mock MCP Server + Full OAuth 2.1 / Fault Injection Harness | **COMPLETE** | `mock_server.py` with cursor pagination, fault rules, indexing lag, external edits |
| **D** | Exhaustive Local Verification + 3 Independent Adversarial Audits + Full R1–R20 Remediation | **COMPLETE** | **79/79 pytest PASSED**, `ruff` 0, `mypy --strict` 0, `bandit -ll` 0, `pip-audit` 0 CVEs |
| **E** | Live OAuth 2.1 Connect + Read-Only Capability & Remote Folder Discovery | **COMPLETE** | Live `auth connect` (OS Keychain + verified automatic silent token refresh), `capabilities --live` (`protocol 2025-11-25`, 12 live tools, fingerprint `93108fa78a27234d`) |
| **F** | Proposed Live Plan & Canary Preparation | **COMPLETE** | Schema-driven `mcp_adapter.py` aligned with all 12 live Sandbar tools |
| **G** | Bounded 1-Log Live Canary & Read-After-Write Verification | **COMPLETE** | Discovered and adapted to live Sandbar block-array `content` format (`[{"type":"text","text":"..."}]`, title in `content[0]`) and `list_artifacts` summary hydration; verified `skipped_unchanged: 1` bit-for-bit match |
| **H** | Universal Context Harvest, Local Staging UI (`/view`) & Compilation | **COMPLETE** | Multi-source local & web-chat ingestion, privacy review, deterministic `<= 900`-word Log compilation, and `<= 140`-char folder instruction generation |
| **I** | Live Production Knowledge-Base Import & Post-Write Verification | **COMPLETE** | Full multi-batch live import verified end-to-end (`100%` ops `VERIFIED`, `0` errors, `0` retries, `0` conflicts, `0` duplicates, live `search` hits confirmed, post-migration backup + `doctor healthy: true`) |
| **J** | Native Stream Conversational Utility Evaluation (12-Dimension Manual Rubric) | **READY FOR USER** | Run `uv run stream-memory evaluate --native-kit` and test natural voice/text conversation directly in the Stream app |

## 2. Incremental Future Updates
To add new context later without duplicating existing Logs:
```bash
uv run stream-memory web-prompts --services chatgpt --mode delta --covered-from-db --raw
uv run stream-memory ingest data/harvested/web_chatgpt_delta.md --json
uv run stream-memory ui --port 4319
uv run stream-memory compile --json
uv run stream-memory plan --mode live --json
uv run stream-memory approve --plan-id <PLAN_ID>
uv run stream-memory apply --plan-id <PLAN_ID> --mode live --json
```
