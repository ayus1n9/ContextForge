"""Guardrail Policy Data Models.

Defines configurable policies governing the multi-layered guardrail pipeline.
"""

from typing import Optional

from pydantic import BaseModel, Field

from backend.app.config import HandlingPolicy, PromptInjectionPolicy, settings


class GuardrailPolicy(BaseModel):
    input_pii_policy: HandlingPolicy = Field(default_factory=lambda: settings.INPUT_PII_POLICY)
    retrieval_pii_policy: HandlingPolicy = Field(default_factory=lambda: settings.RETRIEVAL_PII_POLICY)
    output_pii_policy: HandlingPolicy = Field(default_factory=lambda: settings.OUTPUT_PII_POLICY)
    prompt_injection_policy: PromptInjectionPolicy = Field(default_factory=lambda: settings.PROMPT_INJECTION_POLICY)
    enforce_grounding: bool = Field(default_factory=lambda: settings.ENFORCE_GROUNDING_CHECK)
    enforce_output_sanitization: bool = Field(default_factory=lambda: settings.ENFORCE_OUTPUT_SANITIZATION)
    enforce_safety_disclaimers: bool = Field(default_factory=lambda: settings.ENFORCE_SAFETY_DISCLAIMERS)
    bedrock_guardrail_id: Optional[str] = Field(default_factory=lambda: settings.BEDROCK_GUARDRAIL_ID)
    bedrock_guardrail_version: Optional[str] = Field(default_factory=lambda: settings.BEDROCK_GUARDRAIL_VERSION)


default_guardrail_policy = GuardrailPolicy()
