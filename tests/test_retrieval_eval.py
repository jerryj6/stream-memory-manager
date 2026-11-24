"""Local retrieval evaluation and native Stream evaluation kit tests (Section 27)."""

from __future__ import annotations

from stream_memory_manager.compiler import compile_memory
from stream_memory_manager.db import Database
from stream_memory_manager.evaluator import (
    EvalQuery,
    generate_native_evaluation_protocol,
    run_local_retrieval_evaluation,
)
from stream_memory_manager.registry import KnowledgeRegistry
from tests.conftest import seed_synthetic_records


def test_local_bm25_retrieval_evaluation_on_synthetic_corpus(tmp_db: Database) -> None:
    reg = KnowledgeRegistry(tmp_db)
    seed_synthetic_records(reg, count=5)
    compile_memory(reg, include_index=True, include_briefing=True)

    queries = [
        EvalQuery(
            "syn_q1",
            "exact",
            "What is Alex Mercer studying at Northern State University?",
            ("public policy", "regulatory law"),
        ),
        EvalQuery(
            "syn_q2",
            "paraphrased",
            "Is the mobile civic ledger connected to live data?",
            ("sample json", "proposed"),
        ),
        EvalQuery(
            "syn_q3",
            "indirect",
            "Which USB HID report page did physical keyboard testing confirm?",
            ("0xff60", "orbital65"),
        ),
        EvalQuery(
            "syn_q4",
            "exact",
            "What does trade_ready false mean in my equity research workbench?",
            ("trade_ready", "autonomous trading"),
        ),
        EvalQuery(
            "syn_q5",
            "unknown",
            "What is Alex Mercer's SSN and checking account balance?",
            (),
            expect_unknown=True,
        ),
    ]

    result = run_local_retrieval_evaluation(reg, queries=queries, dataset_name="synthetic_v1")
    assert result["eval_layer"] == "LOCAL_BM25_SIMULATION_ONLY"
    assert "Does NOT measure Sandbar Stream" in result["disclaimer"]
    assert result["queries_passed"] == 5
    assert result["pass_rate"] == 1.0


def test_native_evaluation_protocol_contains_rubric_and_held_out_questions() -> None:
    kit = generate_native_evaluation_protocol()
    assert kit["execution_mode"] == "MANUAL_NATIVE_STREAM_CONVERSATION"
    assert len(kit["rubric_dimensions"]) == 12
    assert len(kit["primary_questions"]) >= 10
    assert len(kit["held_out_paraphrased_questions"]) >= 5
