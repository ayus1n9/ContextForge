"""Amazon Bedrock LLM Provider.

Optional provider using boto3 Converse API / InvokeModel.
Strictly opt-in via LLM_PROVIDER=bedrock.
Handles timeouts, retries, and errors without exposing credentials.
"""

import logging
import time
from typing import Optional

from backend.app.config import settings
from backend.app.llm.base import BaseLLMProvider, LLMResponse
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)

logger = logging.getLogger("aegisrag.llm.bedrock")


class BedrockLLMProvider(BaseLLMProvider):
    """Amazon Bedrock Converse / InvokeModel provider."""

    def __init__(
        self,
        model_id: Optional[str] = None,
        region_name: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ):
        self.model_id = model_id or settings.BEDROCK_MODEL_ID
        self.region_name = region_name or settings.AWS_REGION
        self.timeout_seconds = timeout_seconds or settings.BEDROCK_TIMEOUT_SECONDS
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config

            config = Config(
                connect_timeout=self.timeout_seconds,
                read_timeout=self.timeout_seconds,
                retries={"max_attempts": settings.BEDROCK_MAX_RETRIES, "mode": "standard"},
            )
            # Uses environment/IAM role credentials; never hardcodes secrets
            self._client = boto3.client("bedrock-runtime", region_name=self.region_name, config=config)
        return self._client

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        start_time = time.time()
        try:
            client = self._get_client()

            # Using Converse API format
            messages = [{"role": "user", "content": [{"text": prompt}]}]
            system_list = [{"text": system_prompt}] if system_prompt else []

            response = client.converse(
                modelId=self.model_id,
                messages=messages,
                system=system_list,
                inferenceConfig={
                    "maxTokens": max_tokens,
                    "temperature": temperature,
                },
            )

            latency = (time.time() - start_time) * 1000.0
            content = response["output"]["message"]["content"][0]["text"]
            usage = response.get("usage", {})

            return LLMResponse(
                content=content,
                provider="bedrock",
                model_id=self.model_id,
                input_tokens=usage.get("inputTokens", len(prompt.split())),
                output_tokens=usage.get("outputTokens", len(content.split())),
                latency_ms=round(latency, 2),
                raw_response={"stopReason": response.get("stopReason")},
            )

        except Exception as e:
            latency = (time.time() - start_time) * 1000.0
            error_msg = f"Bedrock invocation failed: {type(e).__name__}"
            logger.error("Bedrock provider error: %s", str(e))

            event = SecurityEvent(
                category=SecurityEventCategory.PROVIDER_ERROR,
                decision=SecurityDecision.ERROR,
                severity=SecuritySeverity.HIGH,
                description=error_msg,
                details={"model_id": self.model_id, "error_type": type(e).__name__},
            )
            audit_logger.log_event(event)

            raise RuntimeError(error_msg) from e
