# Privacy & Security Architecture

## 1. Threat Model & Defense-in-Depth
Stream Memory Manager treats **all ingested source text**, **all remote MCP server responses**, and **all filesystem inputs** as untrusted until validated.

| Threat Vector | Mitigation Implemented |
| :--- | :--- |
| **Sensitive PII / financial / credential leakage** | Deterministic NFKC + zero-width normalized scanning (`privacy.py` & `security.py`) at ingest, privacy review, compilation, export, planning, AND execution preflight. |
| **Zero-width / homoglyph obfuscation** | `normalize_for_scanning()` applies Unicode NFKC normalization and strips zero-width/invisible formatting codepoints (`\u200b`–`\u200f`, `\u202a`–`\u202e`, `\ufeff`, etc.) before running every regex. |
| **Metadata smuggling** | Privacy and prompt-injection scanners inspect ALL rendered fields (`title`, `body`, `category`, `logical_group`, `search_aliases`, `update_triggers`) plus every finalized `CompiledArtifact`. |
| **Prompt injection in ingested exports** | `detect_prompt_injection()` flags override instructions (`IGNORE ALL PREVIOUS INSTRUCTIONS`, approval bypasses, token exfiltration directives), forces `EXCLUDED`, and records a `HIGH` security issue. Ingested text can never invoke actions or self-approve. |
| **Untrusted JSON privilege escalation** | JSON ingestion strips self-asserted `APPROVED` / `PUBLIC` fields, caps evidence classes, rejects reserved internal `logical_id`s, and resets prior `APPROVED` status whenever a record's body changes. |
| **Stale compiled artifact upload** | `exporter.py`, `planner.py`, and `executor.py` verify that `compiled_artifacts.revision_number == memory_records.current_revision` and re-run `assert_record_exportable()` right before writing. |
| **OAuth token & secret exposure** | OS Keychain primary storage (fails closed on `KeyringError`; zero silent plaintext fallback); opt-in local file store uses atomic `0600` temp-file swap + `O_NOFOLLOW`; `redact_secrets()` strips Bearer headers, JWTs, API keys, and JSON-quoted `access_token`/`refresh_token`/`client_secret` across CLI output and error logs. |
| **XSS / injection in OAuth callback or terminal** | Loopback OAuth callback HTML-escapes all query parameters (`html.escape`) and enforces RFC 9207 `iss` + single-capture thread lock; Rich CLI output uses `rich.markup.escape` and `markup=False`. |
| **Cross-account / wrong-endpoint writes** | Strict `--mode` to URL enforcement (`mock` -> loopback only; `live` -> `https://api.sandbar.com/mcp` only); account binding verification before every write; dual refresh + access token revocation on disconnect. |
| **Repository data leakage** | `.gitignore` excludes `data/`, `*.db*`, `credentials/`, `backups/`, `review/`, and `local_*.json`; zero personal data or third-party collaborator literals exist in tracked `src/`, `tests/`, or `docs/`. |

## 2. Privacy Classification & Hard-Block Rules
- **Hard-Blocked Classes (Fail Closed — Cannot Be Compiled or Uploaded):**
  - `EXCLUDED_PRIVACY`: SSNs/tax IDs, payment card numbers, exact financial account balances, identity-theft chronologies, private-review appendix markers, coursework automation identifiers.
  - `EXCLUDED_SECURITY`: API keys (`sk-...`, `ghp_...`, `AKIA...`), JWTs, Bearer tokens, private keys, Tailscale hostnames (`*.ts.net`), `ntfy.sh` private topics, SSH private config/keys, raw session cookies/HAR dumps.
  - `EXCLUDED_CONFIDENTIAL`: Confidential dossiers or owner-local excluded identifiers.
- **Review-Required Classes (Blocked Until Explicit Human Confirmation with `--ack-sensitive`):**
  - `SENSITIVE_REVIEW_REQUIRED`: Phone numbers, street addresses, medical/diagnostic claims. Explicitly preserves nuance: self-reported attention/ADHD concerns paired with explicit negation of a formal diagnosis (`"no formal diagnosis"`) are permitted cleanly without fabricating a clinical claim; unnegated formal diagnosis claims trigger human review.
  - `GENERALIZED_REQUIRED`: Records flagged as needing manual generalization before export.
- **Owner-Local Custom Rules (`data/local_privacy_rules.json`):** User-specific confidential keywords or collaborator repository patterns are loaded at runtime from gitignored `data/local_privacy_rules.json` (mode `0600`) so private terms never appear in tracked source code.
