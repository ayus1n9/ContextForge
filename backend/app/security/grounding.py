"""Contextual Grounding and Citation Verification Layer.

Verifies that model answers are derived directly from retrieved passages.
Detects fabricated citations, hallucinated page numbers, and ensures
safe abstention when retrieved evidence is insufficient.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)

INSUFFICIENT_EVIDENCE_RESPONSE = (
    "The available verified reference documents do not establish sufficient "
    "evidence to answer this question. To ensure safety and accuracy, please "
    "consult the official FAA manuals or certified technical publications."
)


class Citation(BaseModel):
    doc_id: str
    doc_title: str
    page_number: int
    source_url: Optional[str] = None
    is_valid: bool = True


class GroundingEvaluationResult(BaseModel):
    is_grounded: bool = True
    grounding_score: float = 1.0
    citations: List[Citation] = Field(default_factory=list)
    fabricated_citations: List[str] = Field(default_factory=list)
    decision: SecurityDecision = SecurityDecision.ALLOWED
    reason: Optional[str] = None


class GroundingEvaluator:
    """Evaluates contextual support and validates citations against retrieved chunks."""

    def evaluate(
        self,
        query: str,
        answer: str,
        retrieved_chunks: List[Dict[str, Any]],
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> GroundingEvaluationResult:
        """Validate answer grounding and citations against retrieved chunks."""
        # If no chunks were retrieved or evidence was explicitly declared insufficient
        if not retrieved_chunks:
            return GroundingEvaluationResult(
                is_grounded=True,  # Abstaining safely is considered grounded behavior
                grounding_score=0.0,
                citations=[],
                decision=SecurityDecision.ALLOWED,
                reason="No retrieved context available; safe abstention expected.",
            )

        # Extract allowed documents and pages from retrieved chunks
        valid_sources: Dict[str, Set[int]] = {}
        source_titles: Dict[str, str] = {}
        source_urls: Dict[str, Optional[str]] = {}

        for chunk in retrieved_chunks:
            meta = chunk.get("metadata", {})
            doc_id = meta.get("doc_id", "unknown")
            doc_title = meta.get("doc_title", "Unknown Document")
            page = meta.get("page_number", 1)

            if doc_id not in valid_sources:
                valid_sources[doc_id] = set()
            valid_sources[doc_id].add(page)
            source_titles[doc_id] = doc_title
            source_urls[doc_id] = meta.get("source_url")

        # Parse citations from answer text (e.g. [FAA-H-8083, p. 12] or [DocID: doc1, Page: 4])
        extracted_citations = self._extract_citations(answer)
        verified_citations: List[Citation] = []
        fabricated: List[str] = []

        for cited_doc, cited_page in extracted_citations:
            # Check if doc is in retrieved sources
            matching_doc_id = None
            for valid_id, title in source_titles.items():
                if cited_doc.lower() in valid_id.lower() or cited_doc.lower() in title.lower():
                    matching_doc_id = valid_id
                    break

            if not matching_doc_id or (cited_page is not None and cited_page not in valid_sources.get(matching_doc_id, set())):
                fabricated_str = f"Document: '{cited_doc}', Page: {cited_page}"
                fabricated.append(fabricated_str)
            else:
                verified_citations.append(
                    Citation(
                        doc_id=matching_doc_id,
                        doc_title=source_titles[matching_doc_id],
                        page_number=cited_page or 1,
                        source_url=source_urls.get(matching_doc_id),
                        is_valid=True,
                    )
                )

        # Calculate grounding overlap based on key terms from retrieved chunks
        chunk_text = " ".join([c.get("text", "") for c in retrieved_chunks]).lower()
        chunk_words = set(re.findall(r"\b[a-z]{4,}\b", chunk_text))
        answer_words = set(re.findall(r"\b[a-z]{4,}\b", answer.lower()))

        # Remove common English stop words
        stop_words = {
            "this", "that", "these", "those", "with", "from", "have", "been",
            "will", "would", "could", "should", "their", "there", "about",
            "which", "when", "where", "what", "then", "into", "more", "other"
        }
        answer_content_words = answer_words - stop_words

        if answer_content_words:
            overlap = len(answer_content_words.intersection(chunk_words))
            grounding_score = min(1.0, overlap / max(1, len(answer_content_words)))
        else:
            grounding_score = 1.0

        is_grounded = len(fabricated) == 0 and (grounding_score >= 0.20 or INSUFFICIENT_EVIDENCE_RESPONSE in answer)

        if not is_grounded:
            event = SecurityEvent(
                correlation_id=correlation_id or "unknown",
                category=SecurityEventCategory.GROUNDING_FAILURE,
                decision=SecurityDecision.BLOCKED,
                severity=SecuritySeverity.HIGH,
                description=f"Grounding validation failed: {len(fabricated)} fabricated citations or low relevance",
                client_ip=client_ip,
                details={
                    "grounding_score": round(grounding_score, 2),
                    "fabricated_citations": fabricated,
                },
            )
            audit_logger.log_event(event)

            return GroundingEvaluationResult(
                is_grounded=False,
                grounding_score=grounding_score,
                citations=verified_citations,
                fabricated_citations=fabricated,
                decision=SecurityDecision.BLOCKED,
                reason=f"Fabricated citations detected: {', '.join(fabricated)}",
            )

        # If answer has no explicit citations, build citations directly from the top retrieved chunks
        if not verified_citations and retrieved_chunks:
            for chunk in retrieved_chunks[:2]:
                meta = chunk.get("metadata", {})
                doc_id = meta.get("doc_id", "doc")
                verified_citations.append(
                    Citation(
                        doc_id=doc_id,
                        doc_title=meta.get("doc_title", "Technical Reference"),
                        page_number=meta.get("page_number", 1),
                        source_url=meta.get("source_url"),
                        is_valid=True,
                    )
                )

        return GroundingEvaluationResult(
            is_grounded=True,
            grounding_score=grounding_score,
            citations=verified_citations,
            fabricated_citations=[],
            decision=SecurityDecision.ALLOWED,
        )

    def _extract_citations(self, text: str) -> List[Tuple[str, Optional[int]]]:
        """Parse citation tags like [Source: FAA-PHAK, Page: 15] or [Doc, p. 12]."""
        citations = []
        # Pattern 1: [Doc, p. 12] or [Title, Page 12] or [Title, Page: 12]
        matches = re.finditer(r"\[([^,\]]+)(?:,\s*(?:p\.|page:?)\s*(\d+))?\]", text, re.IGNORECASE)
        for m in matches:
            doc_name = m.group(1).strip()
            page = int(m.group(2)) if m.group(2) else None
            # Filter out non-citation brackets like [REDACTED_EMAIL]
            if not doc_name.startswith("REDACTED_") and not doc_name.startswith("!CAUTION"):
                citations.append((doc_name, page))
        return citations


# Default singleton instance
grounding_evaluator = GroundingEvaluator()
