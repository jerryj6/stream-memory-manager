---
name: stream-memory
description: Agent-driven personal context handoff, consolidation, and live Sandbar Stream memory manager. The coding agent itself drives discovery, harvesting, lossless dossier synthesis (zero BYOK/Ollama), official MCP upload, and automated Stream Web verification + permanent archive cleanup.
---

# Stream Memory Manager — Agent-Driven Skill (`SKILL.md`)

You (the coding agent) are the intelligence driving this entire pipeline end-to-end. **`stream-memory`** is your structured patch, handoff compiler, crash-safe MCP uploader, and local inspection dashboard — never bolt on external BYOK/Ollama APIs; use your own reasoning directly to turn scattered multi-platform history into a crisp, lossless **Context Handoff**, synthesize **12–25 dense Topic Dossiers (600–880 words each)** + one **Always-On Briefing**, upload seamlessly to Sandbar Stream via official MCP, and verify & clean up directly in the official **Stream Web App** (`https://stream.sandbar.com`).

---

## Core Operating Rules

1. **Agent-driven, zero BYOK/Ollama:** Never ask the user for OpenAI/Anthropic/Ollama keys. Pull raw handoff bundles with `stream-memory agent-pack`, synthesize consolidated dossiers directly with your own reasoning, and commit them atomically via `stream-memory apply-dossiers`.
2. **Consolidate losslessly — never dump fragments:** Never upload 50+ tiny overlapping notes. Merge across every source into **~12–25 dense, self-contained, voice-friendly Topic Dossiers (600–880 words each, 0 splits, 0 robotic `[Confirmed]` / `Date/Period:` noise)** while preserving 100% of concrete facts, exact model numbers, dates, negative results, NDA boundaries, and caveats.
3. **Protect personal Stream notes & require approval before live writes:** Never mutate the user's live Sandbar Stream account or delete notes without explicit approval. Always keep user-authored Stream voice notes separate from managed Memory dossiers.
4. **Sanctioned paths only:** Authenticate via official Sandbar OAuth 2.1 + PKCE (`api.sandbar.com/mcp`) and drive the official Stream Web UI (`https://stream.sandbar.com`) inside a normal user-authenticated browser session. Never bypass login, scrape private browser cookies, or call undocumented private backend APIs.

---

## Stage 1 — Dynamic Discovery & Selective Harvesting

1. Detect installed local coding agents and git repositories read-only:
   ```bash
   uv run stream-memory detect --json
   ```
2. Ask the user **two concise questions** before reading personal sources:
   - **Which web AI services do you actively use** (`chatgpt`, `claude`, `gemini`, `grok`, `perplexity`, `t3_chat`, `deepseek`, `duck_ai`) — and do you prefer browser-driven extraction or uploading official `.zip`/`.json` exports?
   - **Which detected local agents/repos should be included**, and is anything **off-limits** (NDA projects, confidential repos, finances)?
3. Harvest confirmed local sources (secret-redacted, read-only):
   ```bash
   uv run stream-memory harvest --sources <comma,separated,ids> --json
   ```
4. For each confirmed web AI service, **NEVER rewrite extraction prompts from scratch** — emit the premade static Max-Thinking template directly from the CLI:
   ```bash
   # Initial full extraction:
   uv run stream-memory web-prompts --services chatgpt --mode full --raw

   # Incremental delta extraction (auto-lists already-covered topics from SQLite):
   uv run stream-memory web-prompts --services claude --mode delta --covered-from-db --raw
   ```
   - **MANDATORY:** Before sending in the web AI UI (via your browser/computer-use tool or user paste), switch the web app to **Max / High / Extended Thinking** per `max_thinking_instruction` in `web-prompts --json`.
   - Save each `STREAM_MEMORY_EXPORT v1` response to `data/harvested/web_<service>.md` and ingest it (or parse official `.zip`/`.json` exports via `harvest-export`):
     ```bash
     uv run stream-memory ingest data/harvested/web_<service>.md --json
     uv run stream-memory harvest-export /path/to/export.zip --json
     ```

---

## Stage 2 — Assemble Detailed Context Handoff & Consolidate With Your Own Intelligence

1. Create a pre-consolidation backup and export the single **Agent Consolidation Pack** (connected-component overlap clusters, hygiene flags, and full raw source bodies):
   ```bash
   uv run stream-memory backup --label pre_consolidation --json
   uv run stream-memory agent-pack --output /tmp/stream_agent_pack.json --json
   ```
2. Read `/tmp/stream_agent_pack.json` and use **your own full reasoning** to produce `/tmp/stream_dossiers.json` matching `apply_schema_example`:
   - Group overlapping clusters into **~12–25 dense, self-contained Topic Dossiers** (`<= 880` conservative words each so 0 auto-splits occur).
   - Write natural, direct prose & clean bullets — strip `[Confirmed]` / `[Constraint]` / `Date/Period:` noise and fold redundant AI meta-rules into one canonical Operating Instructions dossier.
   - Distribute miscellaneous saved-memory bullets into their exact home dossiers, then list pure redundant records under `retire_ids`.
   - Preserve **100%** of exact names, numbers, dates, versions, negative results, NDA rules, and caveats.
3. Apply all synthesized dossiers, run privacy review, and compile in **one atomic command**:
   ```bash
   uv run stream-memory apply-dossiers /tmp/stream_dossiers.json --compile --no-index --json
   ```
   Verify `oversized_dossiers == []`, `privacy_summary.hard_blocked == 0`, and `compile.compiled_log_count` matches your intended dossier count with 0 splits.
4. Optionally open **Stream Memory Studio** (`http://127.0.0.1:4319/view`) if the user wants to visually review or tweak anything before live sync:
   ```bash
   uv run stream-memory ui --port 4319 --no-browser
   ```

---

## Stage 3 — Official Sandbar MCP Upload & Obsolete Note Staging

1. Connect once via official OAuth 2.1 + PKCE (tokens stored in OS Keychain):
   ```bash
   uv run stream-memory auth connect --scope "stream stream.write" --confirm-account
   ```
2. Inspect exact live diff read-only (automatically distinguishes managed Memory notes from user-authored Stream voice notes):
   ```bash
   uv run stream-memory inspect-live --json
   ```
3. Present exact counts to the user (`stale_in_stream`, `changed_local`, `new_local`, and preserved `user_notes_in_memory`) and get explicit approval before mutating live Stream.
4. Once approved:
   - Move obsolete managed Memory notes into `Memory Archive` via official MCP `set_note_folder` (preserving user-authored personal voice notes untouched):
     ```bash
     uv run stream-memory reset-memory --stale-only --confirm-reset --json
     ```
   - Plan, approve, and upload the new consolidated Topic Dossiers with paced read-after-write verification:
     ```bash
     uv run stream-memory plan --mode live --json
     uv run stream-memory approve --plan-id <PLAN_ID> --actor user --note "User approved"
     uv run stream-memory apply --plan-id <PLAN_ID> --mode live --json
     ```
   - Verify live MCP search retrieval on 3–4 realistic questions:
     ```bash
     uv run stream-memory search-live "realistic question covering core context" --json
     ```

---

## Stage 4 — Automated Driving of Stream Web (`https://stream.sandbar.com`) for Real Deletion, Briefing & End-to-End Verification

Because Sandbar's official MCP server intentionally omits `delete_note` and `set_briefing`, **do not stop after moving obsolete notes into `Memory Archive`**. Use your browser / computer-use tool to drive the official **`https://stream.sandbar.com`** web app directly (using the user's normal signed-in browser session — pause cleanly if the user needs to sign in once):

1. **Permanently Delete `Memory Archive`:** Navigate to `Memory Archive` in `https://stream.sandbar.com` and permanently delete the quarantined old notes / empty folder through the official UI. Never touch personal notes outside `Memory Archive`. Re-check `uv run stream-memory inspect-live --json` until `archive_count == 0`.
2. **Save the Always-On Stream Briefing:** Copy the compiled Briefing (`meta_mcp_briefing` from Studio Tab 3 or SQLite) and save it into the user's Briefing / About Me field in `https://stream.sandbar.com`.
3. **Visual & Conversational Verification:** Confirm in `https://stream.sandbar.com` that `Memory` displays the exact expected dense Topic Dossiers cleanly (no splits, no leftover duplicates) and optionally test a live conversational question in Stream to verify end-to-end recall.
