# MCP Adapter Architecture (`mcp_adapter.py`)

`src/stream_memory_manager/mcp_adapter.py` wraps the official Model Context Protocol Python SDK (`mcp==2.3.0`) over Streamable HTTP (`streamable_http_client`) with strict zero-retry, zero-redirect, fail-closed write safety.

## 1. Critical `mcp==2.3.0` + `httpx2` Findings Resolved in Code
Direct inspection and live localhost testing of `mcp==2.3.0` + `httpx2==2.16.2` uncovered four concrete SDK behaviors that would cause silent duplicate writes or misclassified failures if left unguarded:

| SDK Finding | Impact if Unmitigated | Implemented Safeguard |
| :--- | :--- | :--- |
| **`streamable_http_client()` returns a 2-tuple** `(read_stream, write_stream)` (breaking change from v1.x 3-tuple) | Runtime unpack failure | Explicitly unpacks 2-tuple and verifies via `mypy --strict` + live localhost tests. |
| **HTTP `401` / `429` swallowed into nested `ExceptionGroup([MCPError(-32603)])`** | Rate limits and expired tokens misclassified as `AmbiguousWriteError` (`BLOCKED`) | Attaches a scoped `httpx2` `event_hooks={"response": [...]}` recording ONLY `POST` `tools/call` / `initialize` / `tools/list` to `self.server_url` (ignoring unrelated `GET` 405 noise) + recursive `BaseExceptionGroup` unwrapping. |
| **`stream_within_origin` follows same-origin 307/308 POST redirects** despite `follow_redirects=False` | Silent duplicate POST write replay on redirect | Configures `httpx2.AsyncHTTPTransport(retries=0, verify=True)`, `follow_redirects=False`, AND `max_redirects=0` on the MCP adapter client. |
| **`OAuthClientProvider` skips refresh on server-side `401`** if local expiry clock hasn't tripped | Premature auth failure or interactive prompt during non-interactive execution | Performs explicit single-attempt RFC 9728/8414-validated refresh via `refresh_stored_tokens_if_possible()` with JWT `sub` continuity validation. |

## 2. Error Classification Rules (Fail-Closed on Writes)
Every MCP response and exception is classified strictly according to `is_write`:
- **Confirmed HTTP `401` / OAuth error / `"read-only"` / `"expired"` / `"revoked"`** -> `AuthorizationRequiredError` (safe pre-write pause -> `PAUSED_AUTHORIZATION`; post-write verification pause -> `PAUSED_VERIFICATION_AUTH`).
- **Confirmed HTTP `429` or JSON `"rate limit"` / `"too many requests"`** -> `RateLimitError` preserving exact `Retry-After` seconds (`PAUSED_RATE_LIMIT` or `PAUSED_VERIFICATION_RATE_LIMIT`).
- **Confirmed optimistic-concurrency error (`"changed since"`, `"expected_last_update_ts"`, `"conflict"`)** -> `CONFLICT_ERROR` (`CONFLICTED`).
- **Explicit confirmed pre-commit validation rejections** (e.g., `"exceeds 1,000 words"`, `"exceeds 30 characters"`, `"folder instruction exceeds"`, `"unsupported tool"`) -> `CONFIRMED_REJECTED_WRITE` (`FAILED_CONFIRMED`). Never matches bare numbers like `"140"` or `"401"` in arbitrary strings.
- **ANY network timeout, TCP reset, EOF, HTTP 5xx, malformed JSON, `isError=True` raw text error, or unrecognized write tool error** -> **`AmbiguousWriteError` -> `UNCERTAIN_REMOTE_OUTCOME`**. Never treated as `FAILED_CONFIRMED`; never blindly retried.

## 3. Capability Discovery & Schema Fingerprinting
`discover_capabilities()` calls `initialize` and `tools/list`, extracts exact tool names and parameter schemas (`folder_id`, `expected_last_update_ts`, `idempotency_key`, etc.), detects whether `create_note`/`create_log`, `update_log`, `set_briefing`, and `get_briefing` exist, and computes a deterministic SHA-256 `schema_fingerprint`. Before executing any plan, `ExecutionEngine` re-runs discovery and fails closed (`SchemaDriftError`, invalidating the plan) if the live fingerprint diverges from the planned snapshot.

## 4. Fail-Closed Pagination
`list_artifacts()` traverses cursor pagination (`before` -> `nextBefore`) up to `max_pages` (default 50). If a cursor repeats (loop) or `nextBefore` remains non-empty after `max_pages`, the adapter raises `StreamMemoryError` rather than silently returning a truncated folder listing that could mislead planning into creating duplicates.
