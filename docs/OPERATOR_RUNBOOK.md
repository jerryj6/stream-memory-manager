# Operator Runbook

Concise operational playbooks for every non-happy-path state reported by `stream-memory status --json` or `stream-memory doctor --json`.

## 1. Plan Paused: `AUTHORIZATION_REQUIRED` (`ExitCode 4`)
- **Cause:** Access token expired (1h), refresh token expired (30d), max connection expired (90d), token revoked, or scope is read-only (`stream` without `stream.write`).
- **Playbook:**
  1. Do **NOT** delete the plan or recreate the DB. Operations may be paused in `PAUSED_AUTHORIZATION` (pre-write) or `PAUSED_VERIFICATION_AUTH` (post-write verification only).
  2. Ask the user to re-authenticate: `uv run stream-memory auth login --mode live`.
  3. Resume safely: `uv run stream-memory resume <PLAN_ID> --mode live --json`. Post-write paused ops will **only** run read-only verification (zero duplicate writes).

## 2. Plan Paused: `RATE_LIMIT_PAUSED` (`ExitCode 8`)
- **Cause:** Server returned repeated HTTP `429` or structured rate-limit responses.
- **Playbook:**
  1. Check `rate_limit.cooldown_remaining_seconds` in `status --json`.
  2. Wait until cooldown reaches `0`.
  3. Resume cleanly: `uv run stream-memory resume <PLAN_ID> --mode live --json`.

## 3. Plan Blocked: `AMBIGUOUS_REMOTE_OUTCOME` (`ExitCode 7`) or `records_uncertain > 0`
- **Cause:** Network drop, process crash, HTTP 5xx, malformed JSON, or raw `isError=True` occurred after a write entered `REQUEST_IN_FLIGHT`.
- **Playbook:**
  1. **NEVER** create a new plan or blindly retry!
  2. Run read-only reconciliation: `uv run stream-memory reconcile <PLAN_ID> --mode live --json`.
  3. If the Log committed remotely, `reconcile` uniquely adopts its `remote_id`, verifies normalized content, and marks it `VERIFIED`.
  4. If `reconcile` moves the op to `BLOCKED` (0 remote matches found), inspect the `Memory` folder manually in the Sandbar Stream app before deciding whether to re-plan.

## 4. Plan Blocked: `PARTIAL_VERIFICATION` (`ExitCode 6`)
- **Cause:** Server acknowledged `create_note`, but `searchIndexStatus` / `get_artifact` lagged past `max_verification_attempts_per_op`.
- **Playbook:** Wait 30–60 seconds and run `uv run stream-memory verify <PLAN_ID> --mode live --json`.

## 5. Plan Blocked: `BLOCKED_CONFLICT` (`ExitCode 5`)
Inspect the exact cause in `status --json` / `conflicts --json`:
- **Account Mismatch:** Signed into a different Sandbar account than bound to `<PLAN_ID>`. Disconnect and sign into the original bound account.
- **Duplicate `Memory` Folders:** User account has 2+ folders named `Memory`. Merge or rename the duplicate directly in the Stream app, then re-plan.
- **External Edit Conflict (`CONFLICTED`):** User edited the target folder instruction or Log directly in Stream (`expected_last_update_ts` mismatch). Inspect the live Stream content; do not force overwrite.
- **Schema Drift (`INVALIDATED`):** Live `tools/list` schema fingerprint changed since planning. Run `reconcile <PLAN_ID> --mode live` if any ops were in-flight, inspect `capabilities --live --json`, then build and approve a fresh plan.
- **Lock Contention (`LockContentionError`):** Another process holds the account writer lock. Run `doctor --json` to view the holder PID/host/nonce; wait for it to finish (if dead, the OS kernel automatically releases `flock`).

## 6. Cancelling Remaining Unsent Operations (`pause`)
```bash
uv run stream-memory pause <PLAN_ID> --json
```
Atomically cancels only not-yet-dispatched pre-write operations (`CANCELLED_BEFORE_WRITE`) under writer lock while leaving already-dispatched or verified operations untouched and warning that already-created Logs require manual deletion in Stream.
