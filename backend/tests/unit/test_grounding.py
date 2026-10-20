"""Unit Tests for Contextual Grounding and Citation Verification."""

import pytest
from backend.app.observability.security_events import SecurityDecision
from backend.app.security.grounding import (
    INSUFFICIENT_EVIDENCE_RESPONSE,
    GroundingEvaluator,
)


@pytest.fixture
def evaluator():
    return GroundingEvaluator()


def test_grounded_answer_with_valid_citation(evaluator):
    chunks = [
        {
            "chunk_id": "chunk-1",
            "text": "The four forces of flight are lift, weight, thrust, and drag.",
            "metadata": {
                "doc_id": "faa-phak-ch05",
                "doc_title": "FAA Pilot Handbook - Chapter 5 Aerodynamics",
                "page_number": 1,
            },
        }
    ]
    query = "What are the four forces of flight?"
    answer = "The four fundamental forces are lift, weight, thrust, and drag. [FAA Pilot Handbook - Chapter 5 Aerodynamics, Page: 1]"

    res = evaluator.evaluate(query=query, answer=answer, retrieved_chunks=chunks)
    assert res.is_grounded is True
    assert res.decision == SecurityDecision.ALLOWED
    assert len(res.citations) >= 1
    assert len(res.fabricated_citations) == 0


def test_fabricated_citation_blocked(evaluator):
    chunks = [
        {
            "chunk_id": "chunk-1",
            "text": "The four forces of flight are lift, weight, thrust, and drag.",
            "metadata": {
                "doc_id": "faa-phak-ch05",
                "doc_title": "FAA Pilot Handbook - Chapter 5 Aerodynamics",
                "page_number": 1,
            },
        }
    ]
    query = "What are the four forces of flight?"
    # Answer cites a non-existent document or page
    answer = "The forces are lift and drag. [Secret NASA Blueprint, Page: 99]"

    res = evaluator.evaluate(query=query, answer=answer, retrieved_chunks=chunks)
    assert res.is_grounded is False
    assert res.decision == SecurityDecision.BLOCKED
    assert len(res.fabricated_citations) > 0


def test_safe_abstention_recognized_as_grounded(evaluator):
    chunks = []
    query = "What is the capital of Mars?"
    answer = INSUFFICIENT_EVIDENCE_RESPONSE

    res = evaluator.evaluate(query=query, answer=answer, retrieved_chunks=chunks)
    assert res.is_grounded is True
    assert res.decision == SecurityDecision.ALLOWED
