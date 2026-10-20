"""Deterministic Mock LLM Provider.

Provides deterministic, grounded Q&A responses for local testing and CI/CD
without requiring any network access, API keys, or cloud credentials.
Treats retrieved context passages strictly as data and refuses to follow
indirect prompt injection instructions embedded within passages.
"""

import re
import time
from typing import Optional

from backend.app.config import settings
from backend.app.llm.base import BaseLLMProvider, LLMResponse
from backend.app.security.grounding import INSUFFICIENT_EVIDENCE_RESPONSE


class MockLLMProvider(BaseLLMProvider):
    """Deterministic mock model simulator with grounding synthesis."""

    def __init__(self, latency_ms: Optional[int] = None):
        self.latency_ms = (
            latency_ms
            if latency_ms is not None
            else settings.MOCK_PROVIDER_RESPONSE_LATENCY_MS
        )

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        start_time = time.time()
        if self.latency_ms > 0:
            time.sleep(self.latency_ms / 1000.0)

        # Extract <RETRIEVED_CONTEXT> and <USER_QUERY>
        context_match = re.search(r"<RETRIEVED_CONTEXT>([\s\S]*?)<\/RETRIEVED_CONTEXT>", prompt)
        query_match = re.search(r"<USER_QUERY>([\s\S]*?)<\/USER_QUERY>", prompt)

        context_text = context_match.group(1).strip() if context_match else ""
        query_text = query_match.group(1).strip() if query_match else prompt.strip()

        # Check if context is empty or declared absent
        if not context_text or "[No relevant passages retrieved]" in context_text:
            content = INSUFFICIENT_EVIDENCE_RESPONSE
        else:
            # Parse individual passages and citations from context
            passages = re.findall(
                r"--- PASSAGE \d+ \(Source: ([^,]+), Page: (\d+)\) ---\n([\s\S]*?)(?=(?:--- PASSAGE|\Z))",
                context_text,
            )

            # Analyze query terms
            query_words = set(re.findall(r"\b[a-z]{4,}\b", query_text.lower()))

            matching_passages = []
            for source_title, page_num, p_text in passages:
                # Check keyword overlap between query and passage
                p_words = set(re.findall(r"\b[a-z]{4,}\b", p_text.lower()))
                overlap = query_words.intersection(p_words)
                if overlap:
                    matching_passages.append((source_title.strip(), int(page_num), p_text.strip(), len(overlap)))

            if not matching_passages:
                content = INSUFFICIENT_EVIDENCE_RESPONSE
            else:
                # Sort matching passages by overlap
                matching_passages.sort(key=lambda x: x[3], reverse=True)
                best_source, best_page, best_text, _ = matching_passages[0]

                # Synthesize concise grounded response
                # Take first 1-2 sentences of the best matching passage
                sentences = [s.strip() for s in best_text.split(".") if s.strip()]
                summary = ". ".join(sentences[:2]) + "." if sentences else best_text[:200]

                content = (
                    f"According to verified documentation, {summary} "
                    f"[{best_source}, Page: {best_page}]"
                )

        latency = (time.time() - start_time) * 1000.0
        return LLMResponse(
            content=content,
            provider="mock",
            model_id="mock-deterministic-v1",
            input_tokens=len(prompt.split()),
            output_tokens=len(content.split()),
            latency_ms=round(latency, 2),
        )


# Default singleton instance
mock_llm_provider = MockLLMProvider()
