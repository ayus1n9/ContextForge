"""PII and Sensitive Information Detection & Redaction Layer.

Provides policy-driven redaction (BLOCK, REDACT, ALLOW) across:
1. User input prompts
2. Retrieved document chunks
3. Generated LLM responses

Detects Emails, Phone numbers, SSNs, Credit Cards (with Luhn check),
and synthetic Canary/API secrets.
Never exposes raw PII or secret values in security logs or findings.
"""

import re
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from backend.app.config import HandlingPolicy
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)


class PIIDetectionResult(BaseModel):
    has_pii: bool = False
    decision: SecurityDecision = SecurityDecision.ALLOWED
    detected_types: List[str] = Field(default_factory=list)
    redacted_text: str
    match_counts: Dict[str, int] = Field(default_factory=dict)
    reason: Optional[str] = None


def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validate credit card number using the Luhn algorithm."""
    digits = [int(d) for d in card_number_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PIIRedactor:
    """PII Detector and Redactor supporting multiple policy layers."""

    # Patterns for regex-based PII detection
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
    )
    # International & US phone formats
    PHONE_PATTERN = re.compile(
        r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    )
    # US Social Security Number pattern (XXX-XX-XXXX)
    SSN_PATTERN = re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
    )
    # Credit Card candidate pattern (13 to 19 digits with optional hyphens/spaces)
    CARD_CANDIDATE_PATTERN = re.compile(
        r"\b(?:\d[ -]*?){13,19}\b"
    )
    # Synthetic secrets, canary tokens, and credential patterns
    SECRET_PATTERN = re.compile(
        r"\b(CANARY-[A-Za-z0-9_-]+|AEGIS_SECRET_[A-Za-z0-9_-]+|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b",
        re.IGNORECASE,
    )

    def process(
        self,
        text: str,
        policy: HandlingPolicy,
        stage: str = "INPUT",  # "INPUT", "RETRIEVAL", "OUTPUT"
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        redteam_case_id: Optional[str] = None,
    ) -> PIIDetectionResult:
        """Scan and process text according to the specified HandlingPolicy."""
        detected_types: List[str] = []
        match_counts: Dict[str, int] = {}
        redacted = text

        # 1. Canary / Synthetic Secrets
        secret_matches = self.SECRET_PATTERN.findall(text)
        if secret_matches:
            detected_types.append("SECRET_KEY")
            match_counts["SECRET_KEY"] = len(secret_matches)
            redacted = self.SECRET_PATTERN.sub("[REDACTED_SECRET]", redacted)

        # 2. Email Addresses
        email_matches = self.EMAIL_PATTERN.findall(text)
        if email_matches:
            detected_types.append("EMAIL")
            match_counts["EMAIL"] = len(email_matches)
            redacted = self.EMAIL_PATTERN.sub("[REDACTED_EMAIL]", redacted)

        # 3. SSN
        ssn_matches = self.SSN_PATTERN.findall(text)
        if ssn_matches:
            detected_types.append("SSN")
            match_counts["SSN"] = len(ssn_matches)
            redacted = self.SSN_PATTERN.sub("[REDACTED_SSN]", redacted)

        # 4. Credit Card (with Luhn verification)
        valid_card_count = 0
        for match in self.CARD_CANDIDATE_PATTERN.finditer(text):
            candidate = match.group(0).strip()
            clean_digits = "".join(c for c in candidate if c.isdigit())
            if 13 <= len(clean_digits) <= 19 and luhn_checksum_valid(clean_digits):
                valid_card_count += 1
                redacted = redacted.replace(candidate, "[REDACTED_CARD]")
        if valid_card_count > 0:
            detected_types.append("CREDIT_CARD")
            match_counts["CREDIT_CARD"] = valid_card_count

        # 5. Phone Numbers
        # Run phone pattern after card pattern to avoid treating card numbers as phones
        phone_matches = self.PHONE_PATTERN.findall(redacted)
        if phone_matches:
            detected_types.append("PHONE")
            match_counts["PHONE"] = len(phone_matches)
            redacted = self.PHONE_PATTERN.sub("[REDACTED_PHONE]", redacted)

        has_pii = len(detected_types) > 0

        if not has_pii:
            return PIIDetectionResult(
                has_pii=False,
                decision=SecurityDecision.ALLOWED,
                detected_types=[],
                redacted_text=text,
                match_counts={},
            )

        # Determine decision based on policy
        if policy == HandlingPolicy.BLOCK:
            decision = SecurityDecision.BLOCKED
            final_text = text  # Blocked request won't proceed anyway
            reason = f"Request blocked due to prohibited sensitive data: {', '.join(detected_types)}"
        elif policy == HandlingPolicy.REDACT:
            decision = SecurityDecision.REDACTED
            final_text = redacted
            reason = f"Sensitive data detected and redacted: {', '.join(detected_types)}"
        else:  # ALLOW
            decision = SecurityDecision.ALLOWED
            final_text = text
            reason = f"Sensitive data detected but permitted by policy: {', '.join(detected_types)}"

        # Log security audit event (scrubbed, never storing raw sensitive values!)
        event = SecurityEvent(
            correlation_id=correlation_id or "unknown",
            category=SecurityEventCategory.PII_DETECTED,
            decision=decision,
            severity=SecuritySeverity.HIGH if "SECRET_KEY" in detected_types else SecuritySeverity.MEDIUM,
            description=f"[{stage}] {reason}",
            client_ip=client_ip,
            redteam_case_id=redteam_case_id,
            details={
                "stage": stage,
                "detected_types": detected_types,
                "match_counts": match_counts,
                "policy": policy.value,
            },
        )
        audit_logger.log_event(event)

        return PIIDetectionResult(
            has_pii=True,
            decision=decision,
            detected_types=detected_types,
            redacted_text=final_text,
            match_counts=match_counts,
            reason=reason,
        )


# Default singleton instance
pii_redactor = PIIRedactor()
