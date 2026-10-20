"""Guardrail Pipeline Orchestrator.

Sequences end-to-end multi-layered defense controls:
1. Rate Limiting Check
2. Input Validation (length, encoding, null-bytes)
3. Direct Prompt Injection Detection (BLOCK / DETECT_ONLY)
4. Input PII Redaction (BLOCK / REDACT / ALLOW)
5. Optional Bedrock Input Guardrails
6. Authorized Retrieval & Relevance Thresholding
7. Retrieval Context PII Redaction & Source Validation
8. Context-Delimited Prompt Synthesis
9. Model Execution (Local Mock or AWS Bedrock)
10. Output Canary Secret & XSS Neutralization
11. Output PII Redaction
12. Grounding and Citation Verification
13. Educational Safety Disclaimer Attachment
"""

import time
import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.app.config import HandlingPolicy, PromptInjectionPolicy
from backend.app.guardrails.bedrock_guardrails import (
    BedrockGuardrailResult,
    bedrock_guardrails_client,
)
from backend.app.guardrails.policy import GuardrailPolicy, default_guardrail_policy
from backend.app.llm.base import BaseLLMProvider
from backend.app.llm.mock_provider import mock_llm_provider
from backend.app.llm.prompts import SYSTEM_INSTRUCTION, construct_rag_prompt
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)
from backend.app.retrieval.retriever import Retriever, retriever
from backend.app.retrieval.source_validation import source_validator
from backend.app.security.access_control import UserContext
from backend.app.security.grounding import (
    Citation,
    GroundingEvaluationResult,
    grounding_evaluator,
)
from backend.app.security.input_validation import input_validator
from backend.app.security.output_filter import OutputValidationResult, output_filter
from backend.app.security.pii_redaction import PIIDetectionResult, pii_redactor
from backend.app.security.prompt_injection import (
    InjectionDetectionResult,
    prompt_injection_detector,
)
from backend.app.security.rate_limits import rate_limiter


class PipelineSecurityReport(BaseModel):
    rate_limited: bool = False
    input_valid: bool = True
    input_validation_error: Optional[str] = None
    prompt_injection: InjectionDetectionResult = Field(default_factory=InjectionDetectionResult)
    input_pii: PIIDetectionResult = Field(
        default_factory=lambda: PIIDetectionResult(redacted_text="")
    )
    retrieved_chunks_count: int = 0
    authorized_chunks_count: int = 0
    bedrock_guardrail_input: BedrockGuardrailResult = Field(default_factory=BedrockGuardrailResult)
    output_validation: OutputValidationResult = Field(
        default_factory=lambda: OutputValidationResult(sanitized_text="")
    )
    output_pii: PIIDetectionResult = Field(
        default_factory=lambda: PIIDetectionResult(redacted_text="")
    )
    grounding: GroundingEvaluationResult = Field(default_factory=GroundingEvaluationResult)
    final_decision: SecurityDecision = SecurityDecision.ALLOWED
    blocking_reason: Optional[str] = None


class GuardrailPipelineResponse(BaseModel):
    answer: str
    citations: List[Citation] = Field(default_factory=list)
    correlation_id: str
    security_report: PipelineSecurityReport
    provider: str
    model_id: str
    latency_ms: float


class GuardrailPipeline:
    """Orchestrates all security guardrails across query intake, retrieval, and generation."""

    def __init__(
        self,
        llm: Optional[BaseLLMProvider] = None,
        doc_retriever: Optional[Retriever] = None,
        policy: Optional[GuardrailPolicy] = None,
    ):
        self.llm = llm or mock_llm_provider
        self.retriever = doc_retriever or retriever
        self.policy = policy or default_guardrail_policy

    def process_query(
        self,
        query: str,
        user: Optional[UserContext] = None,
        client_ip: Optional[str] = None,
        correlation_id: Optional[str] = None,
        redteam_case_id: Optional[str] = None,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> GuardrailPipelineResponse:
        """Run a query through the full defense-in-depth pipeline."""
        start_time = time.time()
        corr_id = correlation_id or str(uuid.uuid4())
        client = client_ip or "127.0.0.1"
        user_ctx = user or UserContext()

        report = PipelineSecurityReport()

        # ---------------------------------------------------------
        # STAGE 1: Rate Limiting
        # ---------------------------------------------------------
        is_allowed_rate, _ = rate_limiter.is_allowed(client)
        if not is_allowed_rate:
            report.rate_limited = True
            report.final_decision = SecurityDecision.BLOCKED
            report.blocking_reason = "Client rate limit exceeded"

            audit_logger.log_event(
                SecurityEvent(
                    correlation_id=corr_id,
                    category=SecurityEventCategory.RATE_LIMIT_EXCEEDED,
                    decision=SecurityDecision.BLOCKED,
                    severity=SecuritySeverity.MEDIUM,
                    description="Client rate limit exceeded",
                    client_ip=client,
                    redteam_case_id=redteam_case_id,
                )
            )
            return self._build_response(
                answer="Rate limit exceeded. Please wait before submitting additional requests.",
                report=report,
                corr_id=corr_id,
                start_time=start_time,
            )

        # ---------------------------------------------------------
        # STAGE 2: Input Validation
        # ---------------------------------------------------------
        is_valid_input, input_err = input_validator.validate_query(
            query=query, correlation_id=corr_id, client_ip=client
        )
        if not is_valid_input:
            report.input_valid = False
            report.input_validation_error = input_err
            report.final_decision = SecurityDecision.BLOCKED
            report.blocking_reason = f"Input validation rejected: {input_err}"
            return self._build_response(
                answer=f"Request rejected by input validation: {input_err}",
                report=report,
                corr_id=corr_id,
                start_time=start_time,
            )

        # ---------------------------------------------------------
        # STAGE 3: Direct Prompt Injection Detection
        # ---------------------------------------------------------
        injection_result = prompt_injection_detector.analyze(
            text=query,
            correlation_id=corr_id,
            client_ip=client,
            redteam_case_id=redteam_case_id,
        )
        report.prompt_injection = injection_result
        if injection_result.is_injection and self.policy.prompt_injection_policy == PromptInjectionPolicy.BLOCK:
            report.final_decision = SecurityDecision.BLOCKED
            report.blocking_reason = injection_result.reason
            return self._build_response(
                answer=(
                    "Security Notice: Your request was identified as an adversarial prompt injection "
                    "or unauthorized instruction override and has been blocked."
                ),
                report=report,
                corr_id=corr_id,
                start_time=start_time,
            )

        # ---------------------------------------------------------
        # STAGE 4: Input PII Redaction / Blocking
        # ---------------------------------------------------------
        input_pii_result = pii_redactor.process(
            text=query,
            policy=self.policy.input_pii_policy,
            stage="INPUT",
            correlation_id=corr_id,
            client_ip=client,
            redteam_case_id=redteam_case_id,
        )
        report.input_pii = input_pii_result
        if input_pii_result.has_pii and self.policy.input_pii_policy == HandlingPolicy.BLOCK:
            report.final_decision = SecurityDecision.BLOCKED
            report.blocking_reason = input_pii_result.reason
            return self._build_response(
                answer="Request rejected: Input contains prohibited sensitive personal or credential data.",
                report=report,
                corr_id=corr_id,
                start_time=start_time,
            )

        sanitized_query = input_pii_result.redacted_text

        # ---------------------------------------------------------
        # STAGE 5: Optional Amazon Bedrock Input Guardrails
        # ---------------------------------------------------------
        bedrock_in = bedrock_guardrails_client.evaluate(
            text=sanitized_query, source="INPUT", correlation_id=corr_id
        )
        report.bedrock_guardrail_input = bedrock_in
        if bedrock_in.intervened:
            report.final_decision = SecurityDecision.BLOCKED
            report.blocking_reason = "Amazon Bedrock Guardrail intervened on input"
            return self._build_response(
                answer="Security Notice: Request blocked by AWS Bedrock Guardrail policy.",
                report=report,
                corr_id=corr_id,
                start_time=start_time,
            )

        # ---------------------------------------------------------
        # STAGE 6: Authorized Retrieval & Provenance Check
        # ---------------------------------------------------------
        retrieved_chunks = self.retriever.retrieve(
            query=sanitized_query,
            user=user_ctx,
            metadata_filter=metadata_filter,
            correlation_id=corr_id,
            client_ip=client,
        )
        report.retrieved_chunks_count = len(retrieved_chunks)
        report.authorized_chunks_count = len(retrieved_chunks)

        # Validate sources
        source_validator.validate_retrieved_sources(retrieved_chunks)

        # ---------------------------------------------------------
        # STAGE 7: Retrieval Context PII Scrubbing
        # ---------------------------------------------------------
        safe_chunks = []
        for chk in retrieved_chunks:
            chk_copy = dict(chk)
            pii_chk = pii_redactor.process(
                text=chk["text"],
                policy=self.policy.retrieval_pii_policy,
                stage="RETRIEVAL",
                correlation_id=corr_id,
                client_ip=client,
                redteam_case_id=redteam_case_id,
            )
            chk_copy["text"] = pii_chk.redacted_text
            safe_chunks.append(chk_copy)

        # ---------------------------------------------------------
        # STAGE 8 & 9: Prompt Synthesis & Model Execution
        # ---------------------------------------------------------
        rag_prompt = construct_rag_prompt(query=sanitized_query, retrieved_chunks=safe_chunks)
        llm_response = self.llm.generate(prompt=rag_prompt, system_prompt=SYSTEM_INSTRUCTION)
        raw_output = llm_response.content

        # ---------------------------------------------------------
        # STAGE 10: Output Canary & XSS Filtering
        # ---------------------------------------------------------
        out_filter_res = output_filter.validate_and_sanitize(
            output_text=raw_output,
            correlation_id=corr_id,
            client_ip=client,
            attach_disclaimer=self.policy.enforce_safety_disclaimers,
            redteam_case_id=redteam_case_id,
        )
        report.output_validation = out_filter_res
        if not out_filter_res.is_safe and out_filter_res.decision == SecurityDecision.BLOCKED:
            report.final_decision = SecurityDecision.BLOCKED
            report.blocking_reason = out_filter_res.reason
            return self._build_response(
                answer=out_filter_res.sanitized_text,
                report=report,
                corr_id=corr_id,
                start_time=start_time,
                llm_response=llm_response,
            )

        sanitized_output = out_filter_res.sanitized_text

        # ---------------------------------------------------------
        # STAGE 11: Output PII Redaction
        # ---------------------------------------------------------
        out_pii_res = pii_redactor.process(
            text=sanitized_output,
            policy=self.policy.output_pii_policy,
            stage="OUTPUT",
            correlation_id=corr_id,
            client_ip=client,
            redteam_case_id=redteam_case_id,
        )
        report.output_pii = out_pii_res
        if out_pii_res.has_pii and self.policy.output_pii_policy == HandlingPolicy.BLOCK:
            report.final_decision = SecurityDecision.BLOCKED
            report.blocking_reason = out_pii_res.reason
            return self._build_response(
                answer="Response blocked: Output contains prohibited sensitive personal or credential data.",
                report=report,
                corr_id=corr_id,
                start_time=start_time,
                llm_response=llm_response,
            )

        final_output_text = out_pii_res.redacted_text

        # ---------------------------------------------------------
        # STAGE 12: Contextual Grounding & Citation Verification
        # ---------------------------------------------------------
        citations: List[Citation] = []
        if self.policy.enforce_grounding:
            grounding_res = grounding_evaluator.evaluate(
                query=sanitized_query,
                answer=final_output_text,
                retrieved_chunks=safe_chunks,
                correlation_id=corr_id,
                client_ip=client,
            )
            report.grounding = grounding_res
            if not grounding_res.is_grounded and grounding_res.decision == SecurityDecision.BLOCKED:
                report.final_decision = SecurityDecision.BLOCKED
                report.blocking_reason = grounding_res.reason
                return self._build_response(
                    answer=(
                        "Security Notice: Generated response failed grounding verification "
                        "(unsupported statements or fabricated citations detected)."
                    ),
                    report=report,
                    corr_id=corr_id,
                    start_time=start_time,
                    llm_response=llm_response,
                )
            citations = grounding_res.citations

        # Completed all guardrails
        report.final_decision = SecurityDecision.ALLOWED
        return self._build_response(
            answer=final_output_text,
            report=report,
            corr_id=corr_id,
            start_time=start_time,
            llm_response=llm_response,
            citations=citations,
        )

    def _build_response(
        self,
        answer: str,
        report: PipelineSecurityReport,
        corr_id: str,
        start_time: float,
        llm_response: Optional[Any] = None,
        citations: Optional[List[Citation]] = None,
    ) -> GuardrailPipelineResponse:
        total_latency = (time.time() - start_time) * 1000.0
        return GuardrailPipelineResponse(
            answer=answer,
            citations=citations or [],
            correlation_id=corr_id,
            security_report=report,
            provider=llm_response.provider if llm_response else "guardrail_layer",
            model_id=llm_response.model_id if llm_response else "none",
            latency_ms=round(total_latency, 2),
        )


# Default singleton pipeline instance
guardrail_pipeline = GuardrailPipeline()
