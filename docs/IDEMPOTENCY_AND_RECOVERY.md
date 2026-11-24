# Idempotency, Crash Recovery, and Reconciliation

## 1. Epistemic Honesty: Why Exactly-Once Is Not Claimed
Without server-enforced idempotency keys across network partitions, distributed write protocols cannot claim mathematical "exactly-once delivery." Stream Memory Manager instead implements **conservative at-most-once write dispatch with read-only reconciliation**:
- Every write is durably journaled as `REQUEST_IN_FLIGHT` **before** touching the socket.
- Transport retries (`retries=0`) and HTTP redirects (`follow_redirects=False`, `max_redirects=0`) are completely disabled on mutating calls.
- Any ambiguous failure (TCP drop after commit, client crash mid-request, HTTP 5xx, malformed JSON, `isError=True` unrecognized text) transitions to `UNCERTAIN_REMOTE_OUTCOME` and **halts further writes** instead of blindly retrying.

## 2. Crash Boundary Matrix (All 8 Boundaries Tested in `test_fault_injection.py`)

| Crash Boundary | Persisted Journal State | Recovery Behavior on Restart | Duplicate Risk |
| :--- | :--- | :--- | :---: |
| `before_journal_persist` | `APPROVED` / `READY` | Normal execution from start | `0` |
| `after_journal_persist` | `REQUEST_PREPARED` | Reset cleanly to `READY` (strictly pre-socket) | `0` |
| `before_dispatch` | `REQUEST_PREPARED` | Reset cleanly to `READY` | `0` |
| `after_ack` (or during socket call) | `REQUEST_IN_FLIGHT` | Promoted to `UNCERTAIN_REMOTE_OUTCOME` -> read-only `reconcile` adopts committed remote Log by normalized title+body hash | `0` |
| `before_id_persist` | `REQUEST_IN_FLIGHT` | Same: read-only `reconcile` discovers remote Log -> `AWAITING_VERIFICATION -> VERIFIED` | `0` |
| `during_verification` | `AWAITING_VERIFICATION` | Resumes read-only verification poll without re-sending `create_note` | `0` |
| `after_verification_before_persist` | `AWAITING_VERIFICATION` | Re-verifies via `get_artifact` and atomically commits `VERIFIED` + `sync_status` | `0` |
| `between_batches` | Completed ops `VERIFIED`; remaining `APPROVED` | Resumes seamlessly from next unexecuted op | `0` |

## 3. Read-Only Ambiguous Write Reconciliation (`reconcile_plan`)
When an operation is in `UNCERTAIN_REMOTE_OUTCOME`, `AWAITING_VERIFICATION`, `PAUSED_VERIFICATION_*`, or `BLOCKED` (after prior commit attempt):
1. `reconcile_plan()` runs strictly read-only MCP calls (`get_artifact`, `list_artifacts`, `search`, `list_folders`, `get_briefing`), even if the plan was later marked `INVALIDATED` by schema drift.
2. **For `CREATE_LOG`:** Computes `claimed_ids` (remote IDs already bound to other operations in the **same** `account_binding_hash`). Searches the `Memory` folder for an unclaimed Log whose normalized title AND `normalized_payload_hash` match **uniquely**:
   - **Exactly 1 unique match:** Adopts the remote `id`, transitions through `AWAITING_VERIFICATION -> VERIFIED`, and atomically syncs `memory_records`!
   - **> 1 match or title match with divergent body:** Transitions to `CONFLICTED` (fail closed).
   - **0 matches (e.g., server dropped before commit or suppressed evidence):** Transitions to `BLOCKED` — **never** auto-creates a duplicate!
3. **For `UPDATE_LOG`:** Reconciles strictly against the operation's exact target `remote_id` via `get_artifact`, verifying the updated `normalized_payload_hash` without scanning unrelated logs.

## 4. Indexing Lag Handling
If `create_note` succeeds with `searchIndexStatus: "pending"` or `get_artifact`/`list_artifacts` transiently lags behind a fresh write, `_verify_operation()` polls read-only within `budget.max_verification_attempts_per_op` using paced monotonic sleeps. If verification still lags when the window closes, the operation transitions to `BLOCKED` (with `remote_id` preserved) so a later read-only `verify` command can confirm it without ever re-sending `create_note`.

## 5. Multi-Part Split Log Tracking
Records exceeding 900 conservative words compile into distinct `artifact_key`s (`<logical_id>:p1`, `<logical_id>:p2`, ...). Each part has its own journaled `operations` row, `remote_id`, and `payload_hash` scoped to `account_binding_hash`, preventing cross-part `remote_id` overwrites and enabling exact orphan detection (`MANUAL_DELETION_REQUIRED`) if a later revision shrinks from 2 parts to 1.
