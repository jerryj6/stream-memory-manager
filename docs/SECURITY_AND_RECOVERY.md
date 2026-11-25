# Security, Privacy & Recovery

## Local-First Privacy Guarantees

- **Zero Telemetry & Gitignored State:** All harvested files, canonical SQLite databases (`data/stream_memory.db`, `0600`), backups, and logs live strictly inside gitignored `data/` (`0700`).
- **Read-Only Secret-Redacted Harvesters:** Local coding-agent harvesters open SQLite databases via `?mode=ro`, skip `.env`, SSH keys, browser cookies, OAuth tokens, `auth.json`, and `agent.db`, and redact detected secrets before writing to disk.
- **Hardened Local Studio (`127.0.0.1`):** Rejects non-loopback `Host` headers (anti-DNS-rebinding), enforces per-process random CSRF tokens (`X-CSRF-Token`) on every POST endpoint, renders user content via DOM `textContent` (no `innerHTML` XSS), and requires explicit confirmation before live remote mutations.
- **Privacy Engine:** Hard-blocks API keys, OAuth/JWT tokens, private keys, SSNs, card numbers, financial account numbers, and prompt injections before compilation or export.

## Sandbar Stream OAuth & Crash-Safe Sync

- **Official OAuth 2.1 + PKCE (`S256`):** Discovers RFC 9728 / 8414 endpoints on `https://api.sandbar.com`, stores tokens in your OS Keychain (`keyring`), refreshes expired 1-hour access tokens silently, and revokes both access + refresh tokens on disconnect (RFC 7009).
- **Zero-Duplicate Write Protection:** Because Sandbar MCP omits `delete_note` and `update_note`, every sync runs through an 18-state SQLite operation journal, single-writer account lock, SQLite-persisted rate limiter (~2s pacing), and mandatory read-after-write `get_artifact` verification (`[{"type":"text","text":"..."}]` block-array hash match). Ambiguous writes halt and reconcile rather than blindly retrying.
- **Safe Quarantine & Reset (`Memory Archive`):** When resetting or removing stale notes, Stream Memory Studio uses official `set_note_folder` (with exact float `lastUpdateUnixTs` optimistic concurrency) to move old notes into `Memory Archive` so `Memory` is immediately clean and you can permanently delete `Memory Archive` inside [stream.sandbar.com](https://stream.sandbar.com).
- **Online SQLite Backups:** `stream-memory backup` creates WAL-safe snapshots with SHA-256 verification metadata; `stream-memory restore` validates checksum + schema integrity before touching the live DB.
