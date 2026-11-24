# Security & Privacy Policy

## Design Posture

**Stream Memory Manager** is strictly **local-first, zero-telemetry, and fail-closed**:

- **Local-only staging & UI:** All databases (`data/stream_memory.db`, `0600`), backups, and harvested files live inside gitignored `data/` (`0700`). The optional staging UI (`stream-memory ui`) binds exclusively to `127.0.0.1`, rejects non-loopback `Host` headers (anti-DNS-rebinding), enforces per-process random CSRF tokens on all POST endpoints, renders user content with `textContent` (no `innerHTML` XSS), and **never** executes live Sandbar remote mutations from browser clicks.
- **Read-only secret-redacted local harvesters:** Local coding-agent harvesters open third-party SQLite stores read-only (`?mode=ro`), explicitly skip `.env`, SSH keys, browser cookies, OAuth tokens, and credential databases (`auth.json`, `agent.db`, `storageState`), and redact detected secret patterns before writing staged digests.
- **Official OAuth 2.1 + PKCE & OS Keyring:** Sandbar MCP authentication uses official RFC 9728/8414/7591 OAuth 2.1 + PKCE (`S256`) and stores tokens in your OS keyring by default (`keyring`), with RFC 7009 dual access+refresh token revocation on disconnect.
- **Fail-closed remote writes:** No remote write runs without explicit human plan approval (`approve --plan-id`). Ambiguous network failures halt immediately rather than blindly retrying non-idempotent `create_note` calls (Sandbar MCP has no delete tool).

## What Never Belongs in Issues or PRs

Please **never** attach or paste:
- Personal context exports, `data/stream_memory.db`, or SQLite backups
- OAuth access/refresh tokens, API keys, or session cookies
- Real Sandbar account IDs, folder UUIDs, or private captures

## Reporting a Vulnerability

If you discover a security vulnerability (e.g., secret-redaction bypass, CSRF/DNS-rebinding issue in `/view`, OAuth redirect flaw, or privacy gate bypass):
1. **Do not** open a public issue with exploit details.
2. Open a private **GitHub Security Advisory** on the repository (or contact the maintainer directly via GitHub).
3. Include minimal synthetic reproduction steps. We aim to acknowledge reports within 48 hours and publish a fix with a regression test.
