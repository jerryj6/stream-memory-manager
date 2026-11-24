# Contributing to Stream Memory Manager

Contributions are welcome — especially new local coding-agent harvesters, web AI platform export parsers, UI improvements, and Sandbar MCP protocol tests.

## Development Setup

```bash
git clone https://github.com/jerryj6/stream-memory-manager.git
cd stream-memory-manager
uv sync
```

## Quality Gates (Run Before Every PR)

Every pull request must pass all five local checks (enforced in GitHub Actions CI):

```bash
uv run ruff format --check src/ tests/
uv run ruff check src/ tests/
uv run mypy src/
uv run bandit -r src/ -c pyproject.toml -ll
uv run pytest -v
```

## Adding a Local Coding-Agent Harvester

1. Add read-only path detection in `detect_local_sources()` inside `src/stream_memory_manager/harvesters.py`.
2. Add the harvester block inside `harvest_local_sources()`:
   - **Never** read `.env`, SSH keys, cookies, or credential databases (extend `SENSITIVE_FILENAME_PARTS` if the tool stores auth in a dedicated DB).
   - Open SQLite databases strictly via read-only URI (`file:<path>?mode=ro`).
   - Pass all extracted text through `redact_secrets(...)` before writing to disk.
3. Add a unit test in `tests/test_harvesters_and_ui.py` using synthetic temporary files (`tmp_path`).

## Adding a Web AI Platform

1. Add a `WebAIServiceSpec` entry in `WEB_AI_CATALOG` (`src/stream_memory_manager/harvesters.py`) including an accurate `max_thinking_instruction`.
2. If the service supports official JSON/ZIP exports, add a parser branch in `parse_web_export_to_markdown()`.
3. Add tests verifying both prompt rendering and secret-redacted export parsing.

## Strict Privacy Hygiene Rule

**Never commit real personal context, real user identifiers, private repo names, or live Sandbar UUIDs/plan IDs** in `src/`, `tests/`, `docs/`, or `examples/`. All fixtures must use clearly synthetic personas (e.g., *Alex Mercer*) and synthetic UUIDs (`00000000-0000-4000-8000-000000000001`).
