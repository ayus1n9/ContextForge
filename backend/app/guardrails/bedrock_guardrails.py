"""Optional Amazon Bedrock Guardrails Integration.

Interfaces with AWS Bedrock Guardrails via apply_guardrail API when configured.
Gracefully reports inactive when running locally without AWS credentials.
"""

import logging
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)

logger = logging.getLogger("aegisrag.guardrails.bedrock")


class BedrockGuardrailResult(BaseModel):
    is_active: bool = False
    action: str = "NONE"  # "NONE", "GUARDRAIL_INTERVENED", "NOT_CONFIGURED"
    intervened: bool = False
    assessment: Dict[str, Any] = Field(default_factory=dict)
    sanitized_text: Optional[str] = None


class BedrockGuardrailsClient:
    """Client for AWS Bedrock apply_guardrail API."""

    def __init__(
        self,
        guardrail_id: Optional[str] = None,
        guardrail_version: Optional[str] = None,
        region_name: Optional[str] = None,
    ):
        self.guardrail_id = guardrail_id or settings.BEDROCK_GUARDRAIL_ID
        self.guardrail_version = guardrail_version or settings.BEDROCK_GUARDRAIL_VERSION
        self.region_name = region_name or settings.AWS_REGION
        self._client = None

    def is_configured(self) -> bool:
        """Check if Bedrock Guardrails credentials and IDs are configured."""
        return bool(self.guardrail_id and self.guardrail_version)

    def _get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("bedrock-runtime", region_name=self.region_name)
        return self._client

    def evaluate(
        self,
        text: str,
        source: str = "INPUT",  # "INPUT" or "OUTPUT"
        correlation_id: Optional[str] = None,
    ) -> BedrockGuardrailResult:
        """Evaluate text using Bedrock Guardrails if configured."""
        if not self.is_configured():
            return BedrockGuardrailResult(
                is_active=False,
                action="NOT_CONFIGURED",
                intervened=False,
            )

        try:
            client = self._get_client()
            content_source = "INPUT" if source.upper() == "INPUT" else "OUTPUT"

            response = client.apply_guardrail(
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion=self.guardrail_version,
                source=content_source,
                content=[{"text": {"text": text}}],
            )

            action = response.get("action", "NONE")
            intervened = action == "GUARDRAIL_INTERVENED"

            sanitized = None
            if intervened:
                outputs = response.get("outputs", [])
                if outputs:
                    sanitized = outputs[0].get("text")

                event = SecurityEvent(
                    correlation_id=correlation_id or "unknown",
                    category=SecurityEventCategory.PROMPT_INJECTION if source == "INPUT" else SecurityEventCategory.OUTPUT_VIOLATION,
                    decision=SecurityDecision.BLOCKED,
                    severity=SecuritySeverity.HIGH,
                    description=f"Bedrock Guardrail intervened on {source}",
                    details={"action": action, "assessments_count": len(response.get("assessments", []))},
                )
                audit_logger.log_event(event)

            return BedrockGuardrailResult(
                is_active=True,
                action=action,
                intervened=intervened,
                assessment=response.get("assessments", {}),
                sanitized_text=sanitized,
            )

        except Exception as e:
            logger.warning("Bedrock Guardrail invocation skipped or failed: %s", str(e))
            return BedrockGuardrailResult(
                is_active=False,
                action="ERROR",
                intervened=False,
                assessment={"error": type(e).__name__},
            )


# Default singleton instance
bedrock_guardrails_client = BedrockGuardrailsClient()
