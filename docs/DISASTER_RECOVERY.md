# Disaster Recovery

## 1. Local SQLite Backup & Verified Restore
Always take a backup before major schema, corpus, or live import milestones:
```bash
uv run stream-memory backup --label pre_live_import --json
```
- Uses SQLite's native Online Backup API (WAL-safe, consistent snapshot).
- Produces a `0600` `.db` file and a companion `.backup.json` containing the SHA-256 digest, schema version, and per-table row counts inside `data/backups/`.
- **Notice:** SQLite backups are unencrypted at rest and protected by OS filesystem permissions (`0700`/`0600`); keep `data/` strictly local and never upload backups to shared cloud storage or git.

### Restoring from a Verified Backup
```bash
uv run stream-memory restore data/backups/<backup_file>.db --json
```
Before touching the live database, `restore_backup()` enforces:
1. Valid 16-byte `SQLite format 3\x00` header (rejects corrupt/non-SQLite files).
2. Exact SHA-256 verification against `.backup.json` (or explicit `--expected-sha256`; refuses unverified restores unless `--allow-unverified-checksum` is passed explicitly).
3. `PRAGMA integrity_check == ok` on the backup file.
4. Presence of all required Stream Memory Manager tables (prevents foreign SQLite DBs from overwriting live state).
5. Exclusive writer lock acquisition and atomic swap (preserving a pre-restore safety copy if an active DB exists).

## 2. Database Corruption Recovery (`ExitCode 9`)
If `data/stream_memory.db` is ever corrupted by disk failure or external tampering:
- Stream Memory Manager **refuses to open or overwrite** the corrupted file (`DatabaseCorruptionError`).
- Copy the corrupted file aside manually for forensics, then restore the latest verified backup via `stream-memory restore` and re-run `reconcile` against live Sandbar Stream if an import was in flight.

## 3. Recovering from an Aborted or Unwanted Remote Import
Because Sandbar's official MCP interface provides **no remote delete tool**:
1. Immediately halt remaining unsent operations: `uv run stream-memory pause <PLAN_ID> --json`.
2. Inspect verified/created Logs via `uv run stream-memory preview --plan-id <PLAN_ID> --json`.
3. Open the Sandbar Stream app -> `Memory` folder -> manually delete unwanted Logs.
4. Re-observe live state (`uv run stream-memory plan --mode live --json`) so local planning synchronizes cleanly with the updated live folder.

## 4. Emergency Credential Revocation
To revoke OAuth access immediately:
```bash
uv run stream-memory auth disconnect --mode live --json
```
This calls RFC 7009 `/revoke` on **both** the refresh token and access token at `https://api.sandbar.com/revoke` and wipes local Keychain/file credentials. You can also revoke the connection directly inside Sandbar's account settings.
