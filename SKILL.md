---
name: stream-memory
description: Universal AI context consolidator & live Sandbar Stream memory manager. Harvests local coding agents + web AI chats (via premade Max-Thinking prompts or exports), consolidates scattered fragments into dense 650-900 word Topic Dossiers + Always-On Briefing, monitors live Sandbar Stream sync & search retrieval, and safely quarantines/resets stale notes into Memory Archive.
---

# Stream Memory Studio — Agent Skill (`SKILL.md`)

Help the user migrate, consolidate, and maintain their personal and technical context in **Sandbar Stream** — cleanly, privately, and with zero scattered duplicates.

**Core rule:** Never dump 50+ tiny overlapping notes into Stream. Always **consolidate** across sources into **~12–25 dense, naturally written Topic Dossiers (650–900 words each)** + one crisp **Always-On Briefing**, and never mutate a user's live Sandbar account without explicit approval.

---

## Step 1 — Launch or Detect (Zero-Clone Ready)

If the user prefers a visual guided flow (no terminal gymnastics), launch **Stream Memory Studio** directly:
```bash
uvx --from git+https://github.com/jerryj6/stream-memory-manager stream-memory
# Or inside a cloned repo:
uv run stream-memory
```
Opens `http://127.0.0.1:4319/view` (4 tabs: **Collect -> Consolidate -> Briefing & Preview -> Live Sync & Monitor**).

For agent-driven execution via CLI, detect installed local coding agents & git repos first:
```bash
uv run stream-memory detect --json
```

---

## Step 2 — Ask the User Two Quick Questions

Before harvesting anything:
1. **Which web AI services do you use** (`chatgpt`, `claude`, `gemini`, `grok`, `perplexity`, `t3_chat`, `deepseek`, `duck_ai`) — and do you have official export `.zip`/`.json` files or want live prompt extraction?
2. **Which detected local agents/repos should be included**, and is anything **off-limits** (NDA projects, client repos, finances)?

---

## Step 3 — Harvest Confirmed Sources (Premade Max-Thinking Prompts — Zero Token Waste)

### Local Agents & Git Repos
```bash
uv run stream-memory harvest --sources <comma,separated,ids> --json
```

### Web AI Chats (NEVER Rewrite Extraction Prompts From Scratch!)
Always emit the static premade template from the CLI with minimal slot personalization:
```bash
# Initial full pass:
uv run stream-memory web-prompts --services chatgpt --mode full --raw

# Incremental delta pass (auto-fills already-staged topics & section numbers from SQLite):
uv run stream-memory web-prompts --services claude --mode delta --covered-from-db --raw
```
- **MANDATORY:** Before sending in any web AI (via browser/computer-use or manual paste), switch the web app to **Max / High / Extended Thinking** (per `max_thinking_instruction` in `web-prompts --json`). Never leave it on Fast/Low/Medium.
- Copy the standardized `STREAM_MEMORY_EXPORT v1` reply into `data/harvested/web_<service>.md` and ingest directly:
  ```bash
  uv run stream-memory ingest data/harvested/web_<service>.md --json
  ```
- Or parse official ChatGPT / Claude / Gemini / DeepSeek / T3 exports directly:
  ```bash
  uv run stream-memory harvest-export /path/to/export.zip --json
  ```

---

## Step 4 — Consolidate Into Dense Topic Dossiers (NOT Scattered Fragments!)

Run the consolidation analyzer to find overlapping records, sparse fragments, and repeated meta-boilerplate:
```bash
uv run stream-memory consolidate --json
```
- **Merge overlapping topics** into unified **650–900 word Topic Dossiers** (one canonical Note per project/domain, written in natural voice-friendly prose — zero `[Confirmed]` tags or repeated AI meta-rules):
  ```bash
  uv run stream-memory merge <id_1> <id_2> --title "Unified Topic Title" --category ENGINEERING --body-file /tmp/merged_dossier.md --json
  ```
- Review/edit visually in Stream Memory Studio (`uv run stream-memory ui --port 4319`) or approve clean dossiers and compile (omitting the noisy separate Table-of-Contents Log when using `<= 25` dense dossiers):
  ```bash
  uv run stream-memory privacy-review --approve-all-clean --json
  uv run stream-memory compile --no-include-index --json
  ```
- **Always hand the user their generated Stream Briefing** (Tab 3 -> 1-click **Copy Briefing**) to paste into their Briefing at `https://stream.sandbar.com`, since Sandbar MCP does not yet expose `set_briefing`.

---

## Step 5 — Live Sync, Retrieval Verification & Safe Reset / Cleanup

```bash
# 1. Connect via official OAuth 2.1 + PKCE (OS Keychain)
uv run stream-memory auth connect --scope "stream stream.write" --confirm-account

# 2. Inspect exact live Memory & Memory Archive diff (read-only)
uv run stream-memory inspect-live --json

# 3. Preview, approve, and push (recommend 1-Note canary first if first run!)
uv run stream-memory plan --mode live --json
uv run stream-memory approve --plan-id <PLAN_ID> --note "User approved"
uv run stream-memory apply --plan-id <PLAN_ID> --mode live --json

# 4. Verify live retrieval quality on real questions
uv run stream-memory search-live "what monitor specs do I want?" --json
```

### Safe Quarantine, Mass Reset & Stream Web Cleanup
Because Sandbar MCP intentionally omits `delete_note`, **never** leave stale/duplicate fragments cluttering `Memory`:
1. **Quarantine stale notes (or reset `Memory` cleanly) via official MCP `set_note_folder`:**
   ```bash
   # Move ONLY stale/superseded notes out of Memory -> Memory Archive:
   uv run stream-memory reset-memory --stale-only --confirm-reset --json

   # Or reset the ENTIRE Memory folder cleanly into Memory Archive:
   uv run stream-memory reset-memory --confirm-reset --json
   ```
2. **Permanent Deletion in Stream Web (`https://stream.sandbar.com`):**
   - Open `https://stream.sandbar.com` -> open the **`Memory Archive`** folder -> permanently delete its notes (or, if the user explicitly asks an agent with browser/computer-use access to empty `Memory Archive`, delete ONLY items inside `Memory Archive` while verifying progress via `uv run stream-memory inspect-live --json` until `archive_count == 0`). Never touch non-archive personal notes.
