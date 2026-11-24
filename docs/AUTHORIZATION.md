# Authorization & Account Binding (`auth.py`)

## 1. Strict Separation of OAuth Authentication vs Write Approval
Signing into Sandbar Stream via OAuth 2.1 **ONLY** authorizes establishing a session and performing read-only discovery (`tools/list`, `list_folders`, `list_artifacts`). It **NEVER** authorizes creating folders, creating Logs, changing folder instructions, or modifying briefings. Every mutating run requires an explicit human approval of a specific immutable `plan_id`.

## 2. Legitimate OAuth 2.1 Flow
`run_interactive_oauth_connect()` implements the official RFC-compliant OAuth 2.1 Authorization Code + PKCE (`S256`) flow:
1. **RFC 9728 Protected Resource Metadata:** Probes `/.well-known/oauth-protected-resource/mcp` (live-verified `200` on `api.sandbar.com`) with fallback to root.
2. **RFC 8414 Authorization Server Metadata:** Fetches `/.well-known/oauth-authorization-server` and verifies `issuer` exact match + allowed origin/TLS rules (`validate_endpoint_url`).
3. **RFC 7591 Dynamic Client Registration:** Registers a localhost loopback client dynamically via `/register`.
4. **Hardened Loopback Callback (`127.0.0.1:<ephemeral_port>/callback`):**
   - Validates `state` and RFC 9207 `iss` parameter when provided.
   - Enforces single-capture thread lock (`409` on duplicate callbacks).
   - HTML-escapes (`html.escape`) any error text rendered to the local browser page.
   - Validates the authorization redirect URL scheme/host before opening the browser.
5. **Credential Storage (`SecureTokenStorage`):**
   - **Default (`--use-keyring`):** Stores tokens and client metadata in the OS Keychain (macOS Keychain / Linux SecretService). **Fails closed** with `AuthorizationRequiredError` if the OS keyring is locked or unavailable — **zero silent fallback to plaintext files**.
   - **Explicit Opt-In (`--file-token-store`):** Writes `0600` files inside `0700` `data/credentials/` via atomic temp-file swap + `O_NOFOLLOW`.

## 3. Single-Attempt Non-Interactive Token Refresh
When a non-interactive command encounters an expired access token (`401`), `refresh_stored_tokens_if_possible()`:
1. Re-validates RFC 9728 / RFC 8414 metadata and issuer continuity.
2. Performs **at most one** `grant_type=refresh_token` POST (with `retries=0`, `follow_redirects=False`, `max_redirects=0`).
3. Verifies JWT `sub` continuity (refusing if the refreshed token belongs to a different account identity!).
4. If refresh fails (e.g., 30-day rolling refresh token expired or 90-day max connection reached), fails closed with `ExitCode.AUTHORIZATION_REQUIRED` so the user can interactively re-authenticate via `auth login`.

## 4. Dual Token Revocation (`auth disconnect`)
`revoke_and_disconnect()` validates the RFC 7009 revocation endpoint (`https://api.sandbar.com/revoke`), revokes **both** the `refresh_token` AND the `access_token` (sending client credentials per registered auth method), and erases local credentials from Keychain/disk.

## 5. Account Binding & Canonical Scoping
`AccountBindingManager` persists `(profile_name, server_url, issuer, account_id, account_id_verified, confirmed_by_user)` hashed into `binding_hash`:
- Every `plan` is bound to an exact `account_binding_hash`.
- Before executing or resuming any plan, `ExecutionEngine` checks the live authenticated `account_id` against the plan's bound `account_id` and fails closed with `AccountMismatchError` (`ExitCode.BLOCKED_CONFLICT`) on any mismatch (e.g., user signed into a secondary account).
- Single-writer locks and rate-limit buckets are keyed by `canonical_account_scope(server_url, account_id, profile_name)` so two profiles targeting the same remote account still serialize writes and share one rate-limit budget.
