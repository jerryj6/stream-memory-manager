# Verification Matrix & Independent Adversarial Audit Record

> [!NOTE]
> Every command, count, and result below reflects **actual local execution** on macOS ARM64 (Python `3.12.4`, `uv 0.11.7`, `pytest 9.2.0`, `mcp 2.3.0`, `sqlite3 3.50.6`). Unexecuted live Sandbar phases are explicitly marked `PENDING HUMAN GATE`.

## 1. Automated Verification Summary

| Verification Gate | Exact Command Executed | Result | Scope |
| :--- | :--- | :---: | :--- |
| **Formatting** | `uv run ruff format --check src/ tests/` | **PASS** (39 files clean) | All source + test files |
| **Static Linting** | `uv run ruff check src/ tests/` | **PASS** (0 issues) | Rules `E,F,I,N,W,UP,B,A,C4,SIM,S,RUF` |
| **Strict Type Checking** | `uv run mypy src/` | **PASS** (0 errors across 26 modules) | `mypy --strict` enabled |
| **Security Static Analysis** | `uv run bandit -r src/ -c pyproject.toml -ll` | **PASS** (0 Medium/High) | Medium+ security findings |
| **Dependency CVE Audit** | `uv run pip-audit` | **PASS** (0 known vulnerabilities) | Full resolved lockfile |
| **Full Automated Test Suite** | `uv run pytest -v` | **PASS (79/79 passed)** | Unit, 324-pair State Machine, Hypothesis, Rate Limit, Persistence, Security, Concurrency, 8-Boundary Fault Injection, OAuth, E2E Scenarios A–O, 600-Record Scale Soak, CLI, R1–R20 Regressions, Universal Harvesters, Premade Max-Thinking Prompt Kit, Ephemeral `/view` UI |
| **Phase E: Live Read-Only Discovery** | `auth connect --scope "stream stream.write" --confirm-account` + `capabilities --live` + `plan --mode live` | **PASS (READ-ONLY, 0 WRITES)** | Live OAuth 2.1 + macOS Keychain, 12 production tools discovered (`93108fa78a27234d`), existing live `Memory` folder detected |
| **Phase G: Live 1-Log Canary** | Bounded 1-Log live canary (`create_note` -> `get_artifact` -> `list_artifacts` -> `plan --mode live`) | **PASS** | Discovered & fixed live Sandbar block-array `content` + `list_artifacts` hydration; confirmed `skipped_unchanged: 1` bit-for-bit hash match |
| **Phase I: Live Full Import** | `approve` + `apply --mode live` + read-only folder & search check | **PASS (100% VERIFIED)** | Full multi-batch live production import completed with `0` duplicates, `0` errors/retries/conflicts, `<= 140`-char folder instruction applied, live `search` active, post-migration backup + `doctor healthy=true` |
| **Phase J: Native Stream Chat Eval** | Manual 12-dimension conversation rubric in Stream app | **READY FOR USER** | Run `uv run stream-memory evaluate --native-kit` and test directly in Stream |

## 2. Independent Adversarial Review & Remediation Log (3 Independent Auditors)
After initial implementation passed 58/58 tests, **three independent read-only adversarial review agents** audited the entire codebase (zero personal data exposed) across:
1. **Distributed Systems & State-Machine Integrity**
2. **Security, Privacy, OAuth & Persistence Hardening**
3. **Testing Rigor, Reconciliation, Compiler & Retrieval Quality**

Every concrete root cause (`R1`–`R20`) was fixed in code AND permanently guarded by automated tests in `tests/test_audit_regressions.py` and `tests/test_state_machine.py`:

| ID | Category | Root Cause Identified by Adversarial Audit | Code Resolution | Locking Regression Test |
| :---: | :--- | :--- | :--- | :--- |
| **R1** | State Machine | Post-write verification 401/429 used pre-write pause states, creating a 2-hop re-dispatch path on `resume` and false `CANCELLED_BEFORE_WRITE` on `pause` | Added `PAUSED_VERIFICATION_AUTH` & `PAUSED_VERIFICATION_RATE_LIMIT`; removed `CANCELLED_BEFORE_WRITE` from `BLOCKED`/`CONFLICTED` | `test_state_machine.py` (324 pairs + 200 Hypothesis traces), `test_r1_*` |
| **R2** | MCP Transport | Unscoped HTTP hook, bare numeric substring heuristics (`"401"`, `"140"`), and `stream_within_origin` 307/308 POST redirects | Scoped hook to `POST` target methods; exact validation phrases only; unrecognized/raw `isError=True` write -> `AmbiguousWriteError`; `max_redirects=0` | `test_r2_*` |
| **R3** | `UPDATE_LOG` | Missing `logical_id`/`revision_number` in payload, missing retroactive privacy preflight, no stale-read retry, broad reconcile scan | Added full metadata, privacy preflight, bounded stale-read retry loop, target-ID strict reconcile, `expected_last_update_ts` conflict handling | `test_r3_*` |
| **R4** | Plan Locking | `approve_plan` lacked DRAFT check & writer lock; `cancel_plan` lacked writer lock & live-row re-read | Wrapped both in `AccountWriterLock` + `BEGIN IMMEDIATE` live state validation | `test_r4_*` |
| **R5** | Multi-Part & Empty Folder | Empty live folder confused with offline dry-run; multi-part splits shared one `remote_id` slot | Added `is_offline_assumption` flag, per-`artifact_key` account-scoped tracking, and `MANUAL_DELETION_REQUIRED` on part shrinkage | `test_r5_*` |
| **R6** | Briefing Guard | Briefing safety guard could overwrite unrelated user briefing or run when `get_briefing` was unsupported | Requires both `supports_set_briefing` AND `supports_get_briefing` AND empty/managed existing briefing | `test_r6_*` |
| **R7** | Pagination | `list_artifacts` silently truncated when hitting `max_pages` | Fails closed with `StreamMemoryError` on `max_pages` overflow or cursor loop; mid-page errors propagate cleanly | `test_r7_*` |
| **R8** | Plan Identity | `plan_id` omitted budget/full payload hashes and reused `CANCELLED`/`INVALIDATED` plans | Included full op payload hashes + budget; mints fresh `_v2` `DRAFT` plan when prior plan is non-`DRAFT` | `test_r8_r9_*` |
| **R9** | Preflight & Reconcile | External `Memory` folder creation caused duplicate folder op; `INVALIDATED` plans could not run read-only reconcile | `RESOLVE_OR_CREATE_FOLDER` adopts preflight-found folder; `reconcile_plan` works read-only on `INVALIDATED`/`BLOCKED` plans | `test_r8_r9_*` |
| **R10** | Locking / RL / Status | Lock/rate-limit keys differed across profiles; `>3600s` cooldown dropped to 0; `doctor` touched lock files; `status` omitted failed/cancelled states | Unified `canonical_account_scope`, clamped cooldown to `3600s`, read-only `O_RDONLY` lock probe in `doctor`, full status breakdown | `test_r10_*` |
| **R11** | CLI Isolation | `mock`/`live` endpoints not strictly isolated; `resume` could default to mutating mode | `--mode mock` loopback-only; `--mode live` official Sandbar host only; `resume` defaults to `DRY_RUN` | `test_r11_*` |
| **R12** | Ingestion Trust | Untrusted JSON could assert `APPROVED` or reserved `logical_id`; `.txt` skipped privacy; revisions kept prior `APPROVED` | Stripped untrusted overrides, rejected reserved IDs, scanned `.txt`, reset `inclusion_decision` on revision changes | `test_r12_r13_*` |
| **R13** | Privacy Evasion | Zero-width chars bypassed regexes; metadata fields un-scanned; stale compiled artifacts & excluded provenance leaked | Added NFKC + invisible-char stripping, full metadata + artifact scanning, revision freshness enforcement, referenced-only provenance export | `test_r12_r13_*` |
| **R14** | OAuth & Secrets | JSON-quoted tokens missed redaction; silent keyring fallback; single-token revoke; unescaped callback HTML; `max_redirects=0` broke interactive OAuth client | Fixed JSON redaction, fail-closed keyring, dual refresh+access revocation, `html.escape` + RFC 9207 `iss`, fixed interactive OAuth client redirect limit | `test_r14_*` |
| **R15** | Backup / Restore | Foreign SQLite DB could overwrite live DB; missing `.backup.json` unchecked; label traversal | Validates header, SHA-256 sidecar, integrity, and all required tables BEFORE touching live DB; regex-validates backup label | `test_r15_*` |
| **R16** | Repo Hygiene | Personal query examples and third-party collaborator repo literal present in tracked code/tests | Scrubbed 100% of personal/third-party literals from `src/` & `tests/`; moved custom rules/queries to gitignored `data/local_*.json` | `rg` zero-hit audit + `test_security.py` |
| **R17** | Reconciliation | 4-digit regex matched non-year IDs; contradictions did not block compile | Named-month + `19xx`/`20xx` bounded parser; open `CONTRADICTION` blocks `compile_memory()` | `test_r17_r18_r19_*` |
| **R18** | Compiler | Split lost fenced code/bullet formatting; title word headroom undercounted; duplicate titles allowed | Atomic Markdown block preservation, `2 * title_words` conservative budget, duplicate-title fail-closed guard | `test_r17_r18_r19_*` |
| **R19** | Evaluation | Evaluator lacked stopwords, MRR, Recall@1/3, category hints, and leaked-secret unknown checks | Added stopword-filtered BM25, MRR, Recall@1, Recall@3, category hints, and privacy-leak failure on `expect_unknown=True` | `test_r17_r18_r19_*` |
| **R20** | Mock Realism | Mock lacked real cursor pagination, `seed_briefing`, external edits, `isError=True`, and consumed `index_delay` inside `list_artifacts` | Added full pagination, mutation helpers, monotonic timestamps, and strict per-attempt index delay verified by Scenario F (`verification_attempts >= 2`) | `test_scenarios_e2e.py` (Scenario F), `test_r5_*`, `test_r7_*` |
