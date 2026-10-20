"""Output Security and Sanitization Layer.

Inspects generated model responses before returning to users.
Guards against:
- Cross-Site Scripting (XSS) and dangerous markdown injections
- Canary token and system secret leakage
- Enforces educational aviation safety disclaimers
"""

import html
import re
from typing import List, Optional

from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)

AVIATION_SAFETY_DISCLAIMER = (
    "\n\n> [!CAUTION]\n"
    "> **Aviation Safety Notice**: AegisRAG is an educational document assistant. "
    "This answer is for informational purposes only and must NOT be used as authoritative "
    "operational flight-safety, maintenance, dispatch, or regulatory guidance. "
    "Always consult current official FAA/ICAO manuals and certified flight personnel."
)


class OutputValidationResult(BaseModel):
    is_safe: bool = True
    decision: SecurityDecision = SecurityDecision.ALLOWED
    sanitized_text: str
    violations: List[str] = Field(default_factory=list)
    reason: Optional[str] = None


class OutputFilter:
    """Sanitizes and enforces security policy on model outputs."""

    # XSS and dangerous script patterns
    XSS_PATTERNS = [
        re.compile(r"<script[\s\S]*?>[\s\S]*?<\/script>", re.IGNORECASE),
        re.compile(r"<iframe[\s\S]*?>[\s\S]*?<\/iframe>", re.IGNORECASE),
        re.compile(r"<svg[\s\S]*?>[\s\S]*?<\/svg>", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"data\s*:\s*text\/html", re.IGNORECASE),
        re.compile(r"\bon\w+\s*=", re.IGNORECASE),  # onerror=, onclick=, onload=
    ]

    # Canary / secret leakage patterns
    CANARY_PATTERNS = [
        re.compile(r"\bCANARY-[A-Za-z0-9_-]+\b", re.IGNORECASE),
        re.compile(r"\bAEGIS_SECRET_[A-Za-z0-9_-]+\b", re.IGNORECASE),
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b", re.IGNORECASE),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE),
    ]

    def validate_and_sanitize(
        self,
        output_text: str,
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        attach_disclaimer: bool = True,
        redteam_case_id: Optional[str] = None,
    ) -> OutputValidationResult:
        """Inspect and sanitize generated model output."""
        violations: List[str] = []
        sanitized = output_text

        # 1. Check for Canary Secret Leakage
        for pattern in self.CANARY_PATTERNS:
            if pattern.search(output_text):
                violations.append("CANARY_SECRET_LEAKAGE")
                sanitized = pattern.sub("[REDACTED_CONFIDENTIAL_SECRET]", sanitized)

        # 2. Check for XSS and Dangerous Markup
        xss_detected = False
        for pattern in self.XSS_PATTERNS:
            if pattern.search(output_text):
                xss_detected = True
                violations.append("XSS_INJECTION")
                break

        if xss_detected:
            # HTML-escape raw tags to neutralize script execution
            sanitized = html.escape(sanitized)

        # 3. Check for Secret Leakage Decision
        if "CANARY_SECRET_LEAKAGE" in violations:
            event = SecurityEvent(
                correlation_id=correlation_id or "unknown",
                category=SecurityEventCategory.OUTPUT_VIOLATION,
                decision=SecurityDecision.BLOCKED,
                severity=SecuritySeverity.CRITICAL,
                description="Model output contained confidential canary token or secret",
                client_ip=client_ip,
                redteam_case_id=redteam_case_id,
                details={"violations": violations},
            )
            audit_logger.log_event(event)

            return OutputValidationResult(
                is_safe=False,
                decision=SecurityDecision.BLOCKED,
                sanitized_text="[Security Alert: Response blocked due to attempted confidential data disclosure]",
                violations=violations,
                reason="Response contained canary or confidential credentials",
            )

        # 4. Check for XSS Decision
        if xss_detected:
            event = SecurityEvent(
                correlation_id=correlation_id or "unknown",
                category=SecurityEventCategory.OUTPUT_VIOLATION,
                decision=SecurityDecision.REDACTED,
                severity=SecuritySeverity.HIGH,
                description="Dangerous script/markup in output neutralized via HTML escaping",
                client_ip=client_ip,
                redteam_case_id=redteam_case_id,
                details={"violations": violations},
            )
            audit_logger.log_event(event)

        # 5. Append Safety Disclaimer if configured
        if attach_disclaimer and settings.ENFORCE_SAFETY_DISCLAIMERS:
            if AVIATION_SAFETY_DISCLAIMER not in sanitized:
                sanitized += AVIATION_SAFETY_DISCLAIMER

        return OutputValidationResult(
            is_safe=True,
            decision=SecurityDecision.REDACTED if violations else SecurityDecision.ALLOWED,
            sanitized_text=sanitized,
            violations=violations,
        )


# Default singleton instance
output_filter = OutputFilter()
