# AGENTS.md — Contributor & Agent Operating Guide

For end-user migration instructions, follow **[SKILL.md](SKILL.md)** directly.

## 1. Fast Orientation

```bash
uv run stream-memory status --json
uv run stream-memory doctor --json
uv run stream-memory consolidate --json
```

## 2. Hard Safety & Privacy Rules

1. **Never execute live remote writes** (`apply --mode live`, `resume --mode live`, `reset-memory --confirm-reset`) without explicit human approval.
2. **Never commit personal data, real Sandbar UUIDs, or `data/` files** into tracked `src/`, `tests/`, `docs/`, or `examples/`.
3. **Never bypass OAuth or approval gates**, never read `.env` / SSH keys / cookies / credential DBs from other tools, and never call undocumented private Sandbar endpoints.
4. **Never blindly retry** an ambiguous write (`UNCERTAIN_REMOTE_OUTCOME`). Always run read-only `reconcile` or `inspect-live` first.
5. **Always consolidate, never scatter:** merge overlapping sources into dense 650–900 word Topic Dossiers + one Always-On Briefing rather than dumping fragmented notes.

## 3. Quality Gate Before Every Commit

```bash
uv run ruff format --check src/ tests/
uv run ruff check src/ tests/
uv run mypy src/
uv run bandit -r src/ -c pyproject.toml -ll
uv run pytest -v
```

## 4. Key Modules & Docs

- `src/stream_memory_manager/web_ui.py` — 4-tab **Stream Memory Studio** (`127.0.0.1`, CSRF-protected, SSE live monitor)
- `src/stream_memory_manager/consolidator.py` — TF-IDF overlap detection, hygiene triage, deterministic merge, optional BYOK/Ollama Auto-Merge
- `src/stream_memory_manager/harvesters.py` — 12 read-only local agent/repo harvesters + 8-platform premade Max-Thinking prompt kit (`STREAM_MEMORY_EXPORT v1`)
- `src/stream_memory_manager/mcp_adapter.py` — Live-verified Sandbar Stream MCP client (block-array readback, float `lastUpdateUnixTs` quarantine to `Memory Archive`, live search)
- `src/stream_memory_manager/compiler.py` — Voice-friendly `<= 900`-word semantic compiler & Briefing packer
- `src/stream_memory_manager/executor.py` & `state_machine.py` — 18-state crash-safe journal & read-after-write verification
- **Docs:** [SKILL.md](SKILL.md) | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | [docs/SANDBAR_MCP.md](docs/SANDBAR_MCP.md) | [docs/SECURITY_AND_RECOVERY.md](docs/SECURITY_AND_RECOVERY.md)
