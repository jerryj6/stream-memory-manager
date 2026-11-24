"""Local retrieval evaluation engine & Native Stream manual evaluation harness (Section 27).

Explicitly separates local simulated retrieval scores from measured Sandbar native AI retrieval.
Tracked source contains generic/template evaluation schemas; owner-specific query suites can be
supplied via a gitignored JSON file (`--queries-file`).
"""

from __future__ import annotations

import json
import math
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stream_memory_manager.compiler import load_compiled_artifacts
from stream_memory_manager.models import CompiledArtifact, utc_now_iso
from stream_memory_manager.privacy import scan_text_privacy
from stream_memory_manager.registry import KnowledgeRegistry

TOKEN_RE = re.compile(r"[a-z0-9_+#.-]{2,}")
STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "are",
        "was",
        "not",
        "have",
        "has",
        "been",
        "were",
        "will",
        "into",
        "over",
        "also",
        "more",
        "than",
        "when",
        "where",
        "which",
        "about",
        "what",
        "why",
        "how",
        "who",
        "did",
        "does",
        "should",
        "could",
        "would",
        "you",
        "your",
        "my",
        "am",
        "is",
        "in",
        "on",
        "of",
        "to",
        "at",
        "by",
        "or",
        "an",
        "as",
        "it",
        "be",
        "me",
        "we",
        "our",
        "all",
    }
)


@dataclass(frozen=True)
class EvalQuery:
    query_id: str
    category: str  # exact | paraphrased | indirect | alias | cross_record | temporal | unknown
    question: str
    expected_keywords: tuple[str, ...]
    expected_category_hints: tuple[str, ...] = ()
    expect_unknown: bool = False


def _tokenize(text: str) -> list[str]:
    out: list[str] = []
    for raw in TOKEN_RE.findall(text.lower()):
        cleaned = raw.strip(".-")
        if len(cleaned) >= 2 and cleaned not in STOPWORDS:
            out.append(cleaned)
    return out


class LocalBM25Index:
    """Deterministic stopword-filtered BM25 scorer over compiled Stream Logs."""

    def __init__(
        self,
        artifacts: list[CompiledArtifact],
        *,
        k1: float = 1.5,
        b: float = 0.75,
        exclude_navigation_index: bool = False,
    ) -> None:
        self.docs = [
            a
            for a in artifacts
            if a.artifact_kind == "log"
            and (not exclude_navigation_index or a.logical_id != "core_knowledge_index")
        ]
        self.k1 = k1
        self.b = b
        self._doc_tokens: list[list[str]] = []
        self._doc_tf: list[dict[str, int]] = []
        self._df: dict[str, int] = {}

        for doc in self.docs:
            toks = _tokenize(doc.title) * 2 + _tokenize(doc.body)
            self._doc_tokens.append(toks)
            tf: dict[str, int] = {}
            for tok in toks:
                tf[tok] = tf.get(tok, 0) + 1
            self._doc_tf.append(tf)
            for tok in tf:
                self._df[tok] = self._df.get(tok, 0) + 1

        self._avgdl = (
            sum(len(t) for t in self._doc_tokens) / len(self._doc_tokens)
            if self._doc_tokens
            else 1.0
        )

    def search(self, query: str, *, top_k: int = 5) -> list[tuple[CompiledArtifact, float]]:
        q_tokens = _tokenize(query)
        n_docs = len(self.docs)
        if not n_docs or not q_tokens:
            return []

        scored: list[tuple[CompiledArtifact, float]] = []
        for idx, doc in enumerate(self.docs):
            dl = len(self._doc_tokens[idx]) or 1
            tf_map = self._doc_tf[idx]
            score = 0.0
            for qt in set(q_tokens):
                df = self._df.get(qt, 0)
                if df == 0:
                    continue
                idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
                tf = tf_map.get(qt, 0)
                if tf > 0:
                    score += idf * (
                        (tf * (self.k1 + 1.0))
                        / (tf + self.k1 * (1.0 - self.b + self.b * dl / self._avgdl))
                    )
            if score > 0:
                scored.append((doc, round(score, 4)))
        scored.sort(key=lambda pair: (-pair[1], pair[0].artifact_key))
        return scored[:top_k]


def load_eval_queries_from_json(path: Path) -> list[EvalQuery]:
    """Load an owner-local or synthetic query suite from JSON."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.get("queries", raw) if isinstance(raw, dict) else raw
    queries: list[EvalQuery] = []
    for item in items:
        queries.append(
            EvalQuery(
                query_id=str(item["query_id"]),
                category=str(item.get("category", "exact")),
                question=str(item["question"]),
                expected_keywords=tuple(str(k) for k in item.get("expected_keywords", [])),
                expected_category_hints=tuple(
                    str(c).upper() for c in item.get("expected_category_hints", [])
                ),
                expect_unknown=bool(item.get("expect_unknown", False)),
            )
        )
    return queries


def default_generic_eval_queries() -> list[EvalQuery]:
    """Generic repository-safe evaluation templates (zero hardcoded personal details)."""
    return [
        EvalQuery(
            "q01_operating_rules",
            "exact",
            "How should Stream apply dated memory logs and handle newer corrections?",
            ("dated", "corrections"),
            ("CORE", "PREFERENCES"),
        ),
        EvalQuery(
            "q02_proposal_vs_built",
            "paraphrased",
            "How should proposed architectures be distinguished from implemented code?",
            ("proposed", "implemented"),
            ("CORE", "CIVIC", "ENGINEERING"),
        ),
        EvalQuery(
            "q03_exploratory_ideas",
            "paraphrased",
            "How should exploratory ideas and brainstorming be handled?",
            ("exploratory", "commitment"),
            ("CORE", "PREFERENCES"),
        ),
        EvalQuery(
            "q04_engineering_philosophy",
            "paraphrased",
            "What engineering principles govern local-first reliability and agent ergonomics?",
            ("reliability", "agent"),
            ("ENGINEERING", "CORE"),
        ),
        EvalQuery(
            "q05_active_priorities",
            "temporal",
            "What are the current active projects and priorities versus historical work?",
            ("active", "current"),
            ("CURRENT", "PROJECTS"),
        ),
        EvalQuery(
            "q06_communication_preferences",
            "exact",
            "What communication style and response formatting preferences are recorded?",
            ("preferences", "communication"),
            ("PREFERENCES", "CORE"),
        ),
        EvalQuery(
            "q07_dormant_vs_active",
            "temporal",
            "Which historical or dormant projects should not be conflated with active commitments?",
            ("dormant", "historical"),
            ("CURRENT", "HISTORY", "PROJECTS"),
        ),
        EvalQuery(
            "q08_hardware_software_workflow",
            "exact",
            "What local hardware, software tools, and development workflows are documented?",
            ("hardware", "workflow"),
            ("HARDWARE", "INFRASTRUCTURE", "WORKFLOWS", "ENGINEERING"),
        ),
        EvalQuery(
            "q09_cross_record_synthesis",
            "cross_record",
            "How do technical architecture standards connect to current project workflows?",
            ("architecture", "workflow"),
            ("ENGINEERING", "PROJECTS", "CURRENT"),
        ),
        EvalQuery(
            "q10_unknown_privacy_guard",
            "unknown",
            "What is the exact brokerage balance, SSN, and password?",
            (),
            (),
            expect_unknown=True,
        ),
    ]


def _doc_matches_query(doc: CompiledArtifact, q: EvalQuery) -> tuple[bool, list[str]]:
    text = f"{doc.title}\n{doc.body}".lower()
    matched = [kw for kw in q.expected_keywords if kw.lower() in text]
    kw_ok = (len(matched) / len(q.expected_keywords) >= 0.66) if q.expected_keywords else True
    cat_ok = (
        (doc.category.upper() in q.expected_category_hints) if q.expected_category_hints else True
    )
    return (kw_ok and cat_ok), matched


def run_local_retrieval_evaluation(
    registry: KnowledgeRegistry,
    *,
    queries: list[EvalQuery] | None = None,
    queries_file: Path | None = None,
    dataset_name: str = "local_compiled_logs",
    top_k: int = 5,
) -> dict[str, Any]:
    """Evaluate local retrieval over compiled Stream Logs with MRR, Recall@1, Recall@3, and privacy checks.

    Explicitly labeled as LOCAL simulation; never represented as Sandbar's native retrieval score.
    """
    artifacts = load_compiled_artifacts(registry)
    # Index domain logs separately from the CORE navigation index so the index doesn't mask domain-log ranking
    index = LocalBM25Index(artifacts, exclude_navigation_index=True)
    if queries is not None:
        eval_queries = queries
    elif queries_file is not None and queries_file.exists():
        eval_queries = load_eval_queries_from_json(queries_file)
    else:
        eval_queries = default_generic_eval_queries()

    case_results: list[dict[str, Any]] = []
    passed = 0
    top1_hits = 0
    top3_hits = 0
    mrr_sum = 0.0
    scored_queries = 0

    for q in eval_queries:
        hits = index.search(q.question, top_k=top_k)

        if q.expect_unknown:
            # Verify NO hard-blocked secrets/PII exist anywhere in top retrieved docs (full privacy scanner!)
            leaked_rules: list[str] = []
            for doc, _ in hits:
                findings = scan_text_privacy(doc.title, doc.body)
                leaked_rules.extend(f.rule_id for f in findings if f.severity == "HARD_BLOCK")
            ok = len(leaked_rules) == 0
            matched_kw: list[str] = []
            first_hit_rank: int | None = None
        else:
            scored_queries += 1
            first_hit_rank = None
            best_matched: list[str] = []
            for rank_idx, (doc, _score) in enumerate(hits, start=1):
                is_match, m_kw = _doc_matches_query(doc, q)
                if len(m_kw) > len(best_matched):
                    best_matched = m_kw
                if is_match and first_hit_rank is None:
                    first_hit_rank = rank_idx

            # Also check combined top-3 recall for cross-record queries
            combined_top3 = "\n".join(f"{d.title}\n{d.body}" for d, _ in hits[:3]).lower()
            matched_kw = [kw for kw in q.expected_keywords if kw.lower() in combined_top3]
            cross_recall = (
                len(matched_kw) / len(q.expected_keywords) if q.expected_keywords else 1.0
            )
            cat_in_top3 = (
                any(d.category.upper() in q.expected_category_hints for d, _ in hits[:3])
                if q.expected_category_hints
                else True
            )

            if first_hit_rank == 1:
                top1_hits += 1
            if first_hit_rank is not None and first_hit_rank <= 3:
                top3_hits += 1
            if first_hit_rank is not None:
                mrr_sum += 1.0 / first_hit_rank

            if q.category == "cross_record":
                ok = cross_recall >= 0.66 and cat_in_top3 and len(hits) > 0
            else:
                ok = (first_hit_rank is not None and first_hit_rank <= 3) or (
                    cross_recall >= 0.66 and cat_in_top3 and len(hits) > 0
                )

        if ok:
            passed += 1
        case_results.append(
            {
                "query_id": q.query_id,
                "category": q.category,
                "question": q.question,
                "expect_unknown": q.expect_unknown,
                "passed": ok,
                "first_hit_rank": first_hit_rank,
                "matched_keywords": matched_kw,
                "expected_keywords": list(q.expected_keywords),
                "expected_category_hints": list(q.expected_category_hints),
                "top_hits": [
                    {
                        "artifact_key": doc.artifact_key,
                        "category": doc.category,
                        "title": doc.title,
                        "score": score,
                    }
                    for doc, score in hits[:3]
                ],
            }
        )

    total = len(eval_queries)
    summary = {
        "eval_layer": "LOCAL_BM25_SIMULATION_ONLY",
        "disclaimer": (
            "Measured locally via deterministic stopword-filtered BM25 over compiled domain Logs. "
            "Does NOT measure Sandbar Stream's production search ranking or native conversational AI."
        ),
        "dataset_name": dataset_name,
        "compiled_domain_log_count": len(index.docs),
        "queries_total": total,
        "queries_passed": passed,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "recall_at_1": round(top1_hits / scored_queries, 4) if scored_queries else 0.0,
        "recall_at_3": round(top3_hits / scored_queries, 4) if scored_queries else 0.0,
        "mrr": round(mrr_sum / scored_queries, 4) if scored_queries else 0.0,
        "cases": case_results,
    }

    eval_id = f"eval_{uuid.uuid4().hex[:12]}"
    with registry.db.transaction() as conn:
        conn.execute(
            "INSERT INTO evaluation_runs (eval_id, eval_type, dataset_name, results_json, created_at) VALUES (?, ?, ?, ?, ?);",
            (
                eval_id,
                "local_bm25",
                dataset_name,
                json.dumps(summary, sort_keys=True),
                utc_now_iso(),
            ),
        )
    summary["eval_id"] = eval_id
    return summary


def generate_native_evaluation_protocol(
    *, custom_questions: list[str] | None = None, held_out_questions: list[str] | None = None
) -> dict[str, Any]:
    """Generate the structured manual evaluation kit & scoring rubric for native Stream chat (Section 27.4-27.5)."""
    return {
        "protocol_version": "1.1",
        "execution_mode": "MANUAL_NATIVE_STREAM_CONVERSATION",
        "reason": "Official Sandbar MCP interface does not provide a tool to initiate native Stream voice/chat turns.",
        "rubric_dimensions": [
            "factual_correctness",
            "appropriate_uncertainty",
            "retrieval_completeness",
            "correct_project_attribution",
            "temporal_correctness",
            "cross_record_integration",
            "hallucination_avoidance",
            "irrelevance_avoidance",
            "proposal_vs_implementation_distinction",
            "dormant_vs_active_distinction",
            "privacy_behavior",
            "response_usefulness",
        ],
        "scale": "0 = Fail, 1 = Partial, 2 = Pass (do not invent scores prior to live native runs)",
        "primary_questions": custom_questions
        or [q.question for q in default_generic_eval_queries()],
        "held_out_paraphrased_questions": held_out_questions
        or [
            "How should you separate active project commitments from historical or dormant work?",
            "What rules govern newer user corrections vs older imported context?",
            "Which categories of personal or financial information are intentionally unknown or excluded?",
            "How should you respond when the user thinks aloud about an exploratory idea?",
            "Which architecture specs are proposed-only versus confirmed implemented code?",
        ],
    }
