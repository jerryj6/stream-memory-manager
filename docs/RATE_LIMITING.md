# Rate Limiting & Request Budget Governance (`rate_limit.py`)

Sandbar documents an account-wide limit of roughly **1 search/second (burst 8)** and **1 write/second (burst 5)**, returning HTTP `429` or structured rate-limit text with wait instructions when exceeded.

## 1. Account-Level Persistent Scheduler (`AccountRateScheduler`)
All governed MCP calls (`create_note`, `create_folder`, `update_folder`, `update_log`, `set_briefing`, `search`, `list_artifacts`, `get_artifact`, etc.) flow through a **single shared `AccountRateScheduler`** keyed by `canonical_account_scope(server_url, account_id, profile_name)`:
- **Conservative Default Interval:** `2.0` seconds between consecutive governed requests (50% of Sandbar's documented 1 req/s ceiling) with **zero reliance on burst allowance**.
- **Single Mutating Flight:** An exclusive `asyncio.Lock` (`_mutation_lock`) guarantees at most 1 mutating MCP request is ever in flight.
- **Process-Restart Persistence:** Every scheduled slot and `429` cooldown persists `next_allowed_epoch_ms` into SQLite (`rate_limit_state`). A rapid restart or back-to-back CLI invocation honors the persisted floor and cannot burst.
- **Wall-Clock Jump Immunity:** In-process pacing runs strictly on `clock.monotonic()`; backwards wall-clock jumps (`NTP` adjustment) cannot accelerate request dispatch. Persisted future epochs exceeding 1 hour are clamped to `3600.0` seconds (Audit R10 — never dropped to `0`!).

## 2. `Retry-After` & Backoff Governance (`BackoffPolicy`)
- `parse_retry_after_seconds()` parses both numeric HTTP `Retry-After` headers and structured Sandbar error strings (e.g., `"Please wait 4 seconds before retrying"`).
- `compute_delay()` applies bounded exponential backoff with jitter (`base=2.0s`, `max=60.0s`) and **never shortens** an explicit server-directed `Retry-After` interval (`max(server_retry_after, computed)`).
- Repeated consecutive `429` responses (default `max_consecutive_429s = 3`) trip the pause signal: pre-write operations pause cleanly in `PAUSED_RATE_LIMIT`, while post-write verification reads pause cleanly in `PAUSED_VERIFICATION_RATE_LIMIT` (`ExitCode.TEMPORARY_FAILURE`), persisting cooldown state for safe `resume`.

## 3. Hard Per-Run Request Budgets (`BudgetTracker`)
Every execution plan embeds an immutable `RequestBudget` enforced at runtime (Invariant 15):
- `max_planned_writes` (default `150`, canary `5`)
- `max_verification_attempts_per_op` (default `4`)
- `max_reconciliation_requests` (default `50`)
- `max_consecutive_errors` (default `3`)
- `max_total_retries` (default `10`)

Exhausting any budget threshold halts execution immediately and cleanly reports the exact `budget_snapshot` in JSON output.
