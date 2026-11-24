# AGENTS.md — Authoritative Agent Operating Instructions

Read this file and [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md) **before** inspecting source files or taking any action. This repository implements the standing directive: **agent-intuitive, agent-ergonomic, agent-accretive, coherent, cohesive, modular, interconnected, and resource-efficient**.

## 1. Fast Orientation Loop (`OBSERVE -> ORIENT -> CHOOSE -> ACT -> VERIFY -> ACCRETE`)

Run these two read-only JSON commands first to orient without reading source code or conversation history:

```bash
uv run stream-memory status --json
uv run stream-memory doctor --json
```

`status --json` returns the authoritative compact state snapshot:
- `mode`, `account_binding_hash`, `account_verified`, `capability_fingerprint`
- `canonical_records_{total,approved,pending_review,excluded}` and `compiled_logs_total`
- `active_plan`, `active_plan_status`, `records_{total,verified,pending,uncertain,blocked,conflicted,failed,cancelled}`
- `rate_limit` (`account_key`, `consecutive_429s`, `cooldown_remaining_seconds`, `min_interval_seconds`)
- `blocked_reason`, `remote_writes_allowed`, and exact `next_safe_action`

## 2. Hard Safety & Authorization Boundaries

> [!CAUTION]
> **NEVER VIOLATE THESE RULES:**
> 1. **Never execute live remote writes** (`apply --mode live` or `resume --mode live`) without explicit human approval of the exact immutable `plan_id`.
> 2. **Never commit, copy, or echo private personal data** from gitignored `data/` into tracked `src/`, `tests/`, `docs/`, git commits, or external review contexts.
> 3. **Never bypass OAuth or approval gates**, never read tokens/cookies from other local apps (`.codex`, `.claude`, browser profiles), and never call undocumented private Sandbar endpoints.
> 4. **Never blindly retry** an operation in `UNCERTAIN_REMOTE_OUTCOME`, `AWAITING_VERIFICATION`, `PAUSED_VERIFICATION_AUTH`, or `PAUSED_VERIFICATION_RATE_LIMIT`. Always run read-only `reconcile` or `verify` first.
> 5. **Never claim Sandbar deletion/rollback or native retrieval results** that were not directly observed on the live platform.

## 3. Stable CLI Exit Codes

| Exit Code | Enum | Meaning | Safe Next Action |
| :---: | :--- | :--- | :--- |
| `0` | `SUCCESS` | Completed cleanly | Follow `next_safe_action` |
| `2` | `VALIDATION_ERROR` | Invalid args, mode/endpoint mismatch, schema/word-limit error, or privacy rejection | Fix inputs or run `privacy-review` |
| `3` | `APPROVAL_REQUIRED` | Plan not approved, or sensitive record requires `--ack-sensitive` | Run `preview` and obtain explicit human approval |
| `4` | `AUTHORIZATION_REQUIRED` | Missing, expired, revoked, or read-only OAuth token | Run `auth login` (human browser flow), then `resume` |
| `5` | `BLOCKED_CONFLICT` | Account mismatch, duplicate `Memory` folders, external edit conflict, schema drift, lock contention, or blocked op | Inspect `conflicts` / `status`; never force overwrite |
| `6` | `PARTIAL_VERIFICATION` | Writes acknowledged but not yet verified remotely | Run read-only `verify` after indexing lag |
| `7` | `AMBIGUOUS_REMOTE_OUTCOME` | Network drop/crash/unrecognized error after write dispatch | Run read-only `reconcile` — **never** blind retry |
| `8` | `TEMPORARY_FAILURE` | Rate limit (`429`) pause, budget cap, or transient read error | Wait for `cooldown_remaining_seconds`, then `resume` |
| `9` | `PERMANENT_FAILURE` | Corrupt SQLite DB, tampered backup, or confirmed server rejection | Run `doctor` / inspect `docs/DISASTER_RECOVERY.md` |

## 4. Safe Resumption Protocol

1. Run `uv run stream-memory status --json` and `uv run stream-memory doctor --json`.
2. If `active_plan_status` is `PAUSED` or `EXECUTING`:
   - Check `records_uncertain` and `records_blocked`. If non-zero, run `uv run stream-memory reconcile <PLAN_ID> --mode <mock|live> --json`.
   - If `blocked_reason == "AUTHORIZATION_REQUIRED"`, ask the user to re-authenticate via `auth login`, then run `resume <PLAN_ID> --mode <mock|live>`.
   - If `blocked_reason == "RATE_LIMIT_PAUSED"`, respect `cooldown_remaining_seconds`, then run `resume`.
3. Never delete or recreate `data/stream_memory.db` to "fix" an error. Create a backup (`backup --label pre_fix`) first.
4. Before finishing any code or doc change, run the full verification gate:
   ```bash
   uv run ruff check src/ tests/ && uv run mypy src/ && uv run bandit -r src/ -c pyproject.toml -ll && uv run pytest -v
   ```
5. Update [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md) and [docs/DECISION_LOG.md](docs/DECISION_LOG.md) so the next agent inherits verified state.

## 5. Key Codebase Entry Points

- `src/stream_memory_manager/state_machine.py` — 18-state formal transition graph (324 pairs enforced)
- `src/stream_memory_manager/executor.py` — single-writer journaled execution & read-only reconciliation
- `src/stream_memory_manager/planner.py` — immutable plan builder, offline/live observation, briefing & folder guards
- `src/stream_memory_manager/mcp_adapter.py` — `mcp==2.3.0` Streamable HTTP adapter with zero-retry / zero-redirect write transport
- `src/stream_memory_manager/privacy.py` — NFKC + zero-width normalized secret, privacy, and prompt-injection gate
- `src/stream_memory_manager/compiler.py` — deterministic `<= 900`-word semantic splitter, navigation index, and briefing compiler
- `src/stream_memory_manager/mock_server.py` — stateful localhost OAuth + MCP fault-injection simulator
