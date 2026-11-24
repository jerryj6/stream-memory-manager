# Changelog

All notable changes to **Stream Memory Manager** are documented in this file.

## [0.1.0] — 2026-11-24

### Added
- **Universal Agent Skill (`SKILL.md`):** Drop-in 5-step workflow for Claude Code, OpenAI Codex, Google Antigravity, Cursor, OpenCode, Pi/OMP, Devin, and Windsurf.
- **Read-Only Local Coding-Agent Harvesters (`detect`, `harvest`):** Auto-detects and harvests secret-redacted summaries from 11 local sources (Claude Code, Codex, Antigravity, Cursor, OpenCode, Devin CLI, Pi/OMP, T3 Code, Windsurf/Cline/Roo/Aider, global instruction files, and GitHub CLI `gh`).
- **Premade Max-Thinking Web AI Prompt Kit (`web-prompts`):** Static standardized `STREAM_MEMORY_EXPORT v1` prompt template with minimal slot personalization (`--mode full|delta --covered-from-db --raw`), per-platform max-thinking instructions across 8 web AI platforms (ChatGPT, Claude, Gemini, T3 Chat, Grok, DeepSeek, Duck.ai, Perplexity), and official `.zip`/`.json` export parsing (`harvest-export`).
- **Deterministic Ingestion, Privacy Engine & Reconciliation:** Parses `STREAM_MEMORY_EXPORT v1` (including ChatGPT Copy-button Markdown quirks), numbered master docs, V2 exports, generic Markdown, JSON, and text; blocks leaked secrets/PII/prompt injections; detects contradictions and temporal/evidence supersession.
- **MemoryVault-Inspired Scoring & Ephemeral Local Staging UI (`ui`):** Localhost-only `http://127.0.0.1:4319/view` review app with utility/confidence/recency scoring, inline editing, Approve/Exclude toggles, compiled Stream Log preview, Briefing context packer, anti-DNS-rebinding Host validation, and per-process CSRF protection.
- **Production-Verified Sandbar Stream MCP Client (`auth`, `capabilities`, `plan`, `preview`, `approve`, `apply`, `reconcile`, `resume`):**
  - Official OAuth 2.1 + PKCE (`S256`) with OS keyring storage and automatic silent token refresh.
  - Dynamic `tools/list` schema discovery with drift detection (`schema_fingerprint`).
  - Full support for live Sandbar production block-array `content` readback (`[{"type":"text","text":"..."}]`) and `list_artifacts` summary hydration.
  - 18-state crash-safe operation journal, single-writer account lock, persistent conservative rate limiting, read-after-write verification, and online SQLite backup/restore (`backup`, `restore`, `doctor`).
- **Comprehensive Test & Security Suite:** 79 automated tests (unit, 324-pair state machine + Hypothesis, 8-boundary fault injection, E2E scenarios A–O, scale soak, OAuth, harvesters, staging UI, security), `ruff`, `mypy --strict`, and `bandit -ll`.
