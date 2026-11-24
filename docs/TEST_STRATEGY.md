# Test Strategy & Stateful Mock MCP Architecture

## 1. Test Isolation & Non-Negotiable Ground Truth
- **Autouse Network Isolation (`tests/conftest.py`):** Every test automatically patches `socket.socket.connect` and `socket.create_connection` to **block all non-loopback network destinations**, proving mechanically that local tests can never reach `https://api.sandbar.com/mcp` or any external host.
- **Zero Private Personal Data in Tests:** Every fixture in `tests/` uses synthetic non-sensitive data only.
- **Real Protocol Stack:** End-to-end, OAuth, fault-injection, and regression tests exercise the genuine `mcp==2.3.0` Streamable HTTP client over real localhost TCP sockets against `RunningMockServer` (`mock_server.py`) — never shallow function stubs — and verify zero duplicates independently via `srv.state.ground_truth_logs()`.

## 2. Stateful Localhost Mock MCP Server (`mock_server.py`)
`MockSandbarState` + `RunningMockServer` accurately simulates Sandbar Stream's real protocol surface:
- Full OAuth 2.1 lifecycle (`/.well-known/oauth-protected-resource/mcp`, `/.well-known/oauth-authorization-server`, `/register`, `/authorize`, `/token`, `/revoke` for both refresh and access tokens, JWT `sub` / `exp` / `iss`).
- Configurable server capability variants (`tool_style="note"|"log"`, `supports_update_log`, `supports_briefing`, `supports_get_briefing`, `supports_get_account`, `supports_idempotency_key`, `schema_version_tag`).
- Real cursor-based pagination (`list_page_size`), snippet-only search mode, `set_note_folder`, monotonic `lastUpdateUnixTs` with `expected_last_update_ts` optimistic concurrency rejection, per-attempt read-after-write `index_delay_remaining`, `seed_briefing()`, `external_edit_folder()`, `external_edit_log()`, and `delete_all_logs()`.
- Deterministic fault injection rules (`FaultRule`): `commit_then_drop`, `commit_and_suppress_evidence`, `http_401`, `http_429`, `tool_rate_limit`, `http_500_before_commit`, `malformed_json`, `wrong_id`, `partial_search`, `stale_read`, `pagination_fail`, `tool_is_error_raw`, and `normalization_mode="corrupt_body"`.

## 3. Test Suite Taxonomy (15 Modules, 73 Automated Tests)

| Suite File | Focus Area | Tests |
| :--- | :--- | :---: |
| `tests/test_unit_core.py` | Logical IDs, dual word counting, semantic split, normalization, privacy/ADHD nuance, reconciliation, deterministic plan hashing, ingestion | 7 |
| `tests/test_state_machine.py` | Exhaustive 18×18 = 324 transition pairs, safety invariants, Hypothesis `RuleBasedStateMachine` (200 stateful traces × 35 steps) | 3 |
| `tests/test_properties.py` | Hypothesis property tests: order-independent compilation, zero-token-loss splitting, sensitive data non-leakage, temporal precedence | 4 |
| `tests/test_rate_limit.py` | Conservative 2s spacing, restart floor persistence, backwards wall-clock jump immunity, `Retry-After` preservation, repeated 429 pause, hard budgets | 6 |
| `tests/test_persistence.py` | SQLite WAL & `0600` permissions, corrupted DB refusal, online backup/restore & tamper detection, read-only DB refusal | 4 |
| `tests/test_security.py` | Prompt injection defense, path traversal & endpoint validation, nested secret redaction, tampered export refusal, `.gitignore` verification | 6 |
| `tests/test_concurrency.py` | Same-process and cross-subprocess POSIX `flock` contention, concurrent read-only access, graceful shutdown & clean resume | 3 |
| `tests/test_fault_injection.py` | Crash simulation at all 8 operation boundaries (0 duplicates across every boundary) + malformed/wrong-ID/corrupt-body server defenses | 9 |
| `tests/test_oauth_flow.py` | Interactive OAuth + PKCE, server-side 401 single-attempt silent refresh, fail-closed expired refresh re-auth, RFC 7009 revocation | 1 |
| `tests/test_scenarios_e2e.py` | All 15 mandatory End-to-End Local Scenarios (A through O) over live localhost MCP | 10 |
| `tests/test_scale_soak.py` | 600-record scale soak: ingestion, reconciliation, compilation, planning, journal recovery, and scheduler pacing | 1 |
| `tests/test_retrieval_eval.py` | Local BM25 retrieval evaluation on synthetic corpus + 12-dimension manual native Stream evaluation kit | 2 |
| `tests/test_cli.py` | Full end-to-end CLI JSON contracts and stable exit codes | 1 |
| `tests/test_audit_regressions.py` | Dedicated regression suite locking down all 20 root causes (R1–R20) from the 3 independent adversarial audits | 15 |
| `tests/conftest.py` | Autouse external socket blocker & shared synthetic fixtures | — |
