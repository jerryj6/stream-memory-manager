---
name: migrate-to-stream
description: Universal cross-platform personal & technical context migrator for Sandbar Stream. Auto-detects local coding agents, dynamically asks which web AI services the user uses, extracts & stages everything into a clean local review UI, and safely pushes curated <=900-word Logs into a single Sandbar Stream `Memory` folder via official MCP.
---

# Migrate Your AI Context to Sandbar Stream (`SKILL.md`)

You are helping a user migrate their personal and technical context from all their AI chats and coding agents into **Sandbar Stream** cleanly, privately, and repeatably.

Follow these 5 steps in order. **Never** guess which web AI services the user uses, **never** read `.env` / SSH keys / cookies / tokens from other apps, and **never** push to the user's live Sandbar account without showing a preview and getting explicit confirmation.

---

## Step 1 — Set Up & Auto-Detect Local Coding Agents

```bash
uv sync
uv run stream-memory detect --json
```

This detects installed local coding agents read-only:
- **Claude Code**, **OpenAI Codex**, **Google Antigravity**, **Cursor**, **OpenCode**, **Devin CLI**, **Pi / OMP**, **T3 Code**, **Windsurf / Cline / Roo / Aider**, global `AGENTS.md`/`CLAUDE.md`/`GEMINI.md`, and **GitHub CLI (`gh`)**.

---

## Step 2 — Dynamically Ask the User Which Sources to Pull

Present the detected local sources to the user and **ask two quick questions** before harvesting anything:
1. **Which web AI services do you actually use** and want context pulled from?
   - Choices: `chatgpt`, `claude`, `gemini`, `t3_chat`, `grok`, `deepseek`, `duck_ai`, `perplexity` (or none / already exported).
2. **Which detected local coding agents** should be included, and is there anything **explicitly off-limits** (private client/collaborator repos, finances, health, etc.)?

If the user names private repos/terms to exclude, save them in gitignored `data/local_privacy_rules.json` (`0600`) so they can never leak into compiled output.

---

## Step 3 — Harvest Confirmed Sources (Local + Web)

### A. Local Coding Agents (Only What the User Confirmed)
```bash
uv run stream-memory harvest --sources <comma,separated,ids> --json
```
This writes secret-redacted local digests into `data/harvested/local_<source>.md`.

### B. Web AI Services (Only What the User Confirmed — Premade Prompts + MAX THINKING!)
**Never rewrite extraction prompts from scratch** (that wastes tokens and produces inconsistent formatting). Always emit the static premade template from the CLI with minimal slot personalization:
```bash
# First migration (full):
uv run stream-memory web-prompts --services <comma,separated,web_ids> --mode full --json

# Incremental / delta pass (auto-fills already-covered topics & next section number from SQLite!):
uv run stream-memory web-prompts --services chatgpt --mode delta --covered-from-db --raw
```
Then for each selected web service:
- **If the service has built-in cross-chat memory** (`chatgpt`, `claude`, `gemini`, `grok`, `perplexity`) AND you have browser / computer-use access:
  - Open the user's already-logged-in tab (never bypass logins or CAPTCHAs — pause and let the user sign in if needed).
  - **MANDATORY — Switch to MAX THINKING FIRST:** follow `max_thinking_instruction` from `web-prompts --json` (e.g., ChatGPT -> Heavy/Max/Extended Thinking, Claude -> Extended Thinking, Gemini -> Thinking/Pro, DeepSeek -> DeepThink R1, Grok -> Heavy/Think). Never leave the model on Fast/Low/Medium!
  - Paste the premade standardized prompt verbatim into a fresh Memory-enabled thread (NOT Temporary Chat) and wait until `<!-- END_STREAM_MEMORY_EXPORT -->` finishes streaming.
  - Copy the standardized reply verbatim to `data/harvested/web_<service>_<mode>.md` and ingest directly (`uv run stream-memory ingest data/harvested/web_<service>_<mode>.md --json`) — the parser natively reads `<!-- STREAM_MEMORY_EXPORT v1 -->`, `Category:`, `Status:`, and `Observed:` lines!
- **If the user has an official data export** (`conversations.json` / `.zip` from ChatGPT, Claude, Gemini Takeout, DeepSeek, or T3 Chat):
  ```bash
  uv run stream-memory harvest-export /path/to/export.zip --service <service> --json
  ```
- **For ephemeral chats (`duck_ai`)**: only snapshot currently open tabs if the user points you to them.

---

## Step 4 — Synthesize, Stage, and Review in the Ephemeral Local Web UI

Synthesize the harvested local + web digests into a clean, deduplicated Markdown file using `# 00 — Title` through `# NN — Title` sections (separating confirmed facts, built code, proposed architectures, dormant work, and operating instructions; excluding secrets, exact balances, and one-off noise), then ingest and compile:

```bash
uv run stream-memory ingest data/sources/<synthesized_context>.md --json
uv run stream-memory privacy-review --json
```

Give the user **two ways to review** before anything touches Sandbar:
1. **Visual local staging UI (recommended):**
   ```bash
   uv run stream-memory ui --port 4319
   ```
   Open `http://127.0.0.1:4319/view` — lets the user browse every memory card with utility/confidence scores, edit text inline, toggle Approve/Exclude, and inspect the exact compiled `<= 900`-word Stream Logs + Briefing draft.
2. **Fast chat review:** Walk through any `PENDING_REVIEW` / flagged records in chat, then run:
   ```bash
   uv run stream-memory privacy-review --approve-all-clean --json
   uv run stream-memory compile --json
   ```

---

## Step 5 — Authenticate & Push Safely to Sandbar Stream (Official MCP)

Sandbar MCP has **no delete tool** and enforces **~1 req/sec** + **1,000-word Log limit** + **140-char folder instruction limit**. The built-in pusher handles pacing, OAuth refresh, crash recovery, and zero-duplicate verification automatically:

```bash
# 1. Legitimate OAuth 2.1 login (browser opens; zero writes occur)
uv run stream-memory auth connect --scope "stream stream.write" --confirm-account

# 2. Read-only live capability & folder check
uv run stream-memory capabilities --live --json
uv run stream-memory plan --mode live --json
uv run stream-memory preview --plan-id <PLAN_ID>

# 3. ONLY after user explicitly approves the previewed plan_id:
uv run stream-memory approve --plan-id <PLAN_ID> --note "User approved migration"
uv run stream-memory apply --plan-id <PLAN_ID> --mode live --json
```

If interrupted by network drop, rate limit (`429`), or expired OAuth (`401`), **never** start over — run:
```bash
uv run stream-memory status --json
uv run stream-memory reconcile <PLAN_ID> --mode live --json
uv run stream-memory resume <PLAN_ID> --mode live --json
```
