# Memory Compiler

`src/stream_memory_manager/compiler.py` deterministically transforms approved, exportable canonical records in SQLite into Sandbar Stream-ready artifacts (`compiled_artifacts`), guaranteeing strict platform compliance, order independence, zero silent truncation, and high conversational retrieval quality.

## 1. Compilation Rules & Determinism
- **Order Independence:** Input records are sorted canonically by `(CATEGORY_ORDER[category], logical_id)` (with operating instructions prioritized first at priority 50). Re-ingesting sources in any order produces identical compiled artifacts, identical `payload_hash`, and identical `manifest_hash`.
- **Contradiction Gate:** Compilation fails closed (`ExitCode.BLOCKED_CONFLICT`) if any open `CONTRADICTION` or `TEMPORAL_CONTRADICTION` reconciliation issue affects an approved record (unless explicitly overridden in a controlled diagnostic call).
- **Duplicate Title Rejection:** Compilation tracks normalized rendered titles (`CATEGORY — Subject`) and fails closed if two distinct `logical_id`s collide on the same Stream title, preventing remote adoption ambiguity.
- **Privacy Re-Audit:** Every approved record passes `assert_record_exportable()` and every finalized split Log passes `assert_payload_safe()` across title, body, category, and metadata before writing to `compiled_artifacts`.

## 2. Dual Word Counting & Strict Ceiling (`<= 900` Conservative Words)
Sandbar enforces a hard **1,000-word limit per Log including its title**, without publishing its exact server-side tokenizer. To guarantee zero rejections across hyphenated tokens, URLs, slash-delimited paths, Markdown punctuation, and CJK characters, the compiler computes **two word counts** (`count_words_dual`):
1. `whitespace_words`: standard whitespace-separated tokens (`title + body`).
2. `conservative_words`: splits on whitespace AND internal punctuation/slashes/hyphens (`[\w']+` plus individual CJK ideographs), AND budgets `2 * title_words` for title headroom.

Every compiled Log MUST satisfy `conservative_words <= 900` (a 100-word safety buffer below Sandbar's 1,000-word hard limit).

## 3. Formatting-Preserving Semantic Split
When a canonical record exceeds `900` conservative words, `semantic_split_log()` splits it into coherent, self-contained parts without dropping a single token:
1. Parses Markdown into atomic structural blocks: fenced code blocks (` ``` ... ``` `), contiguous bullet/numbered list blocks, and prose paragraphs.
2. Packs whole blocks first; never breaks a fenced code block unless an individual fenced block alone exceeds the body budget.
3. Splits oversized prose blocks at sentence boundaries, falling back to word chunks (and 60-char slices only for pathological >120-char unbroken tokens).
4. Titles each part cleanly: `CATEGORY — Subject (Part X of Y)` and appends a compact series footer (`Series note: Part X of Y...`).
5. Verified by Hypothesis property testing (`test_property_semantic_split_always_respects_word_ceiling_and_never_drops_tokens`): every part obeys `<= 900` conservative words and preserves 100% of input tokens.

## 4. Generated Companion Artifacts
| Artifact Key | Kind | Limit Enforced | Purpose |
| :--- | :--- | :--- | :--- |
| `<logical_id>:p<n>` | `log` | `<= 900` conservative words | Independently retrievable domain memory Logs in `Memory`. |
| `core_knowledge_index:p<n>` | `log` | `<= 900` conservative words (auto-splits if corpus grows) | `CORE — Knowledge Index` enumerating all active categories and Log titles. |
| `meta_folder_instruction` | `folder_instruction` | `<= 140` characters (exact Sandbar limit; default is 130 chars) | Guides Stream on how to apply `Memory` folder Logs naturally. |
| `meta_briefing_draft` | `briefing` | Compact high-level summary (omitted from remote plans unless both `get_briefing` and `set_briefing` are confirmed live) | Optional turn-level pointer to the `Memory` folder. |

## 5. Normalization & Payload Hashing
Each compiled artifact stores TWO SHA-256 hashes:
- `payload_hash`: Exact SHA-256 of canonical JSON `{"title": ..., "body": ...}`.
- `normalized_payload_hash`: SHA-256 after benign transport normalization (`CRLF -> LF`, trailing line whitespace stripped, collapsed terminal newlines, NFKC). Used during read-after-write verification so benign server newline normalization is accepted while any substantive text corruption, truncation, or wrong-body response is rejected immediately.
