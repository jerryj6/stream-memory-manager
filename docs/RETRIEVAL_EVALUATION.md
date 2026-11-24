# Retrieval & Conversational Utility Evaluation

> [!IMPORTANT]
> **Strict Epistemic Boundary:** Local BM25 evaluation measures **lexical retrievability of compiled Logs offline** (`eval_layer = LOCAL_BM25_SIMULATION_ONLY`). It does **NOT** measure Sandbar Stream's production search ranking, semantic embeddings, memory consolidation, or native conversational AI behavior. Native Stream usefulness can ONLY be scored via live manual conversation in Phase G and Phase J.

## 1. Two-Layer Evaluation Architecture
1. **Layer 1 — Local Deterministic BM25 Simulation (`evaluator.py`):**
   - Indexes compiled domain Logs (excluding `CORE — Knowledge Index` so the navigation log cannot mask domain-log ranking).
   - Applies English stopword filtering and computes **MRR**, **Recall@1**, **Recall@3**, **pass rate**, and **privacy non-leakage** (every `expect_unknown=True` query actively scans ALL compiled artifacts for hard-block patterns and fails if any sensitive content leaked).
   - Supports generic repository-safe query templates (`default_generic_eval_queries()`, 10 queries) and owner-local private suites (`--queries-file data/local_eval_queries.json`, gitignored).
2. **Layer 2 — Native Stream Conversational Evaluation Kit (`stream-memory evaluate --native-kit`):**
   - Because official Sandbar MCP provides no tool to trigger native Stream chat/voice turns, the application outputs a structured **12-dimension manual evaluation rubric** (`0 = Fail, 1 = Partial, 2 = Pass`) with primary and held-out paraphrased questions:
     1. `factual_correctness`
     2. `appropriate_uncertainty`
     3. `retrieval_completeness`
     4. `correct_project_attribution`
     5. `temporal_correctness`
     6. `cross_record_integration`
     7. `hallucination_avoidance`
     8. `irrelevance_avoidance`
     9. `proposal_vs_implementation_distinction`
     10. `dormant_vs_active_distinction`
     11. `privacy_behavior`
     12. `response_usefulness`

## 2. Measured Local BM25 Baseline (Owner Local Corpus — Gitignored `data/`)
Executed locally via `stream-memory evaluate --queries-file data/local_eval_queries.json` (`eval_id = eval_732819a17f5e`) over **56 compiled domain Logs** (57 total Logs including `CORE — Knowledge Index`):

| Metric | Measured Local BM25 Value | Interpretation |
| :--- | :---: | :--- |
| **Eval Layer** | `LOCAL_BM25_SIMULATION_ONLY` | Offline lexical simulation only — NOT Sandbar native score |
| **Compiled Domain Logs Indexed** | `56` | Max `574` conservative words per Log |
| **Queries Evaluated** | `15` (13 retrieval + 2 privacy-unknown) | Covers exact, paraphrased, temporal, cross-record, and unknown-privacy classes |
| **Overall Pass Rate** | `12 / 15` (`0.8000`) | 2/2 privacy-unknown checks passed (zero leaks) |
| **Recall@1 (single-doc strict)** | `0.5385` (`7 / 13`) | 7 queries matched target category + keywords directly at rank #1 |
| **Recall@3 (single-doc strict)** | `0.5385` | Remaining passes combined evidence across top-3 complementary Logs |
| **MRR** | `0.5538` | Honest lexical baseline without synonyms/embeddings |

### Honest Diagnostic Findings from the 3 Local BM25 Misses
1. **Cross-record preference split (`q02`):** Communication contract and decision-making heuristics live in two adjacent `PREFERENCES` Logs; rank #1 retrieved the right category, while the second expected keyword lived in the companion `PREFERENCES` Log (demonstrating why Stream's multi-log retrieval + `CORE — Knowledge Index` matters).
2. **Compound tokenization mismatch (`q07`):** Rank #1 retrieved the exact `HARDWARE` Log, but strict substring matching missed a spaced vs concatenated hardware model token.
3. **High-frequency generic term overlap (`q01`):** Pure lexical BM25 weighted `"priorities"` toward the `CURRENT` technical priorities Log at rank #1 and placed the `ACADEMICS` Log at rank #5 — confirming why native semantic retrieval in Sandbar Stream must still be measured live in Phase J rather than extrapolated from local BM25.

## 3. Native Live Evaluation Status (Phase G & Phase J)
- **Phase G (Canary Smoke Check):** Pending OAuth connect & explicit approval — will ask Stream natively for the synthetic canary fact (`Meridian-7`) to verify whether MCP-authored Logs in `Memory` are actively retrieved by Stream's native chat.
- **Phase J (Full 12-Dimension Rubric):** Pending Phase I completion — scores will ONLY be recorded after real manual conversations in the Sandbar Stream app.
