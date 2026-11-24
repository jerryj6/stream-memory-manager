# Source Provenance & Reconciliation

## 1. Provenance Architecture
Every canonical record revision (`record_revisions`) preserves complete lineage back to its raw source file(s):
- `sources` table records `source_id`, `source_path`, `source_label`, `source_format`, and exact raw `content_sha256`.
- `record_revisions` records `source_refs_json` (e.g., `src_<hash>#v2_01_01`) and `source_hashes_json`.
- Re-ingesting identical content merges provenance references without bumping `revision_number`.
- Sanitized exports (`sanitized_provenance.json`) strictly include **only** sources referenced by approved, exported records — excluded or private sources never leak into exported metadata.

## 2. Supported Ingestion Formats
| Format | Detector | Behavior |
| :--- | :--- | :--- |
| `chatgpt_v2_md` | Headings `# NN-NN — Title` | Parses structured metadata headers, cross-links (`RELATES_TO`), categories (`00`–`13`), evidence classes, and status. |
| `tech_supplement_md` | Headings `# TNN — Title` | Parses technical supplement modules (`T01`–`T12`) with artifact-grounded evidence classes and claims. |
| `markdown` | Generic `# Heading` | Splits top-level sections into clean canonical records. |
| `text` | Plain text fallback | Ingests as a single record with full secret, privacy, and prompt-injection scanning. |
| `json` | `.json` extension | Untrusted JSON hardening: **strips** any self-asserted `inclusion_decision: "APPROVED"` or `privacy_classification: "PUBLIC"` downgrade, **caps** evidence class below `USER_CONFIRMED`, and **rejects** reserved internal `logical_id`s (`core_knowledge_index`, `meta_folder_instruction`, `meta_briefing_draft`, `meta_memory_folder`). |

> [!WARNING]
> **Automatic Private-Path Guard:** `ingest_file()` refuses any path containing `private_appendix`, `private-review`, or a `private/` directory component (excluding macOS's system symlink prefix `/private/{var,tmp,etc}`), preventing accidental ingestion of private review appendices.

## 3. Evidence Authority & Temporal Reconciliation
`src/stream_memory_manager/reconciliation.py` applies deterministic, inspectable precedence rules:

1. **Evidence Authority Hierarchy (highest to lowest):**
   `USER_DIRECTED` > `INDEPENDENTLY_VERIFIED` > `ARTIFACT_INSPECTED` > `USER_CONFIRMED` > `AGENT_REPORTED` > `PROPOSED` > `INFERRED` > `HISTORICAL` > `UNKNOWN` > `SUPERSEDED`.
2. **Temporal Parsing:** Extracts explicit ISO dates (`YYYY-MM-DD`, `YYYY-MM`), named-month dates (`Oct 12, 2026`, `November 2026`), and bounded `19xx`/`20xx` years (ignoring non-year 4-digit IDs such as ticket or hardware model numbers). Older records can never supersede newer user-confirmed facts (verified via Hypothesis property test `test_property_older_evidence_never_supersedes_newer_confirmed_info`).
3. **Structured Supersession & Supplement Links:** Maps narrower earlier summaries to richer artifact-verified modules (`SUPERSEDES` / `SUPPLEMENTS`), marking superseded records `status = SUPERSEDED, destination_eligible = 0` while preserving them intact in local SQLite for auditability.
4. **Exact Deduplication & Semantic Overlap:** Deduplicates exact normalized bodies (preferring destination-eligible, higher-authority winners) and uses an inverted-index token filter + Jaccard similarity (`>= 0.72`) to flag near-duplicate records for review in $O(N)$ typical time rather than $O(N^2)$.
5. **Contradiction Detection:** Equal-priority active records on the same `canonical_subject` with divergent bodies are flagged as `CONTRADICTION` (`HIGH` severity) in `reconciliation_issues`, which blocks `compile_memory()` until resolved.

## 4. Local Source Inventory Audit (Owner Local Environment)
During local discovery, two authoritative migration exports were verified on disk (both ingested locally into gitignored `data/stream_memory.db` only; zero personal content is committed to this repository):
- Consolidated V2 personal context archive (`56` structured records, private appendix already excluded).
- Cross-platform technical supplement (`12` structured technical modules `T01`–`T12`).
- Two referenced earlier/pre-merged variants (a standalone ChatGPT V1 archive and a separate pre-merged personal+technical file) were not present as separate files on disk and were not invented; the canonical registry synthesizes the two verified exports cleanly.
