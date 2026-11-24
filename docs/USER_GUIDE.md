# User Guide

## 1. Local-Only Setup & Daily Knowledge Maintenance
All local operations run offline without connecting a Sandbar account. Private state lives strictly inside gitignored `data/` (`0700` dir / `0600` files).

### Step 1: Optional Owner-Local Privacy Rules
To block private collaborator repository names or confidential terms without putting them in source code, create `data/local_privacy_rules.json` (mode `0600`):
```json
{
  "hard_block_patterns": [
    {
      "rule_id": "custom_confidential_project",
      "regex": "\\bPartnerOrg/PrivateRepo\\b",
      "classification": "EXCLUDED_CONFIDENTIAL"
    }
  ]
}
```

### Step 2: Ingest, Reconcile, and Review Privacy
```bash
uv run stream-memory ingest /path/to/personal_export.md
uv run stream-memory ingest /path/to/technical_supplement.md
uv run stream-memory conflicts
uv run stream-memory privacy-review
```
- Records with hard-block secrets, exact financial balances, credentials, or prompt injection are automatically marked `EXCLUDED`.
- Records flagged for review (e.g., phone numbers or addresses) remain `PENDING_REVIEW`.
- Approve clean unflagged records:
  ```bash
  uv run stream-memory privacy-review --approve-all-clean
  ```
- Explicitly approve or exclude a flagged record after inspecting it (`stream-memory inspect <logical_id>`):
  ```bash
  uv run stream-memory privacy-review --approve <logical_id> --ack-sensitive
  # OR keep excluded:
  uv run stream-memory privacy-review --exclude <logical_id>
  ```

### Step 3: Compile, Dry-Run Plan, Export, and Backup
```bash
uv run stream-memory compile
uv run stream-memory plan --mode dry-run
uv run stream-memory preview --plan-id <PLAN_ID>
uv run stream-memory export --output-dir data/review/stream_ready_export
uv run stream-memory backup --label pre_import
```

## 2. Connecting Live Sandbar Stream (Explicit Human Gates)

> [!CAUTION]
> Sandbar's official MCP interface does **not** support deleting Logs or Folders. Always inspect `preview` carefully and run the small synthetic canary first before approving a full import.

1. **Authenticate via Official OAuth 2.1 (Read-Only Session — Zero Writes):**
   ```bash
   uv run stream-memory auth login --mode live
   ```
   Complete the login in your browser. Tokens are stored in your OS Keychain (`--file-token-store` is available as explicit opt-in if your keyring is unavailable).
2. **Phase E — Read-Only Live Capability & Remote State Discovery:**
   ```bash
   uv run stream-memory capabilities --live --json
   uv run stream-memory plan --mode live --json
   uv run stream-memory preview --plan-id <LIVE_PLAN_ID>
   ```
3. **Explicit Approval & Bounded Execution:**
   ```bash
   uv run stream-memory approve --plan-id <LIVE_PLAN_ID> --note "Reviewed preview and approved"
   uv run stream-memory apply --plan-id <LIVE_PLAN_ID> --mode live
   ```
4. **Revoking Access Anytime:**
   ```bash
   uv run stream-memory auth disconnect --mode live
   ```
   Revokes both refresh and access tokens at `https://api.sandbar.com/revoke` and clears local credentials.
