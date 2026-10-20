"""Prompt Injection Defense Layer.

Provides multi-stage deterministic and heuristic detection of direct prompt injection,
jailbreak attempts, roleplay hijacking, and boundary delimiter spoofing.
"""

import re
from typing import List, Optional

from pydantic import BaseModel, Field

from backend.app.config import PromptInjectionPolicy, settings
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)


class InjectionDetectionResult(BaseModel):
    is_injection: bool = False
    decision: SecurityDecision = SecurityDecision.ALLOWED
    confidence: float = 0.0
    matched_categories: List[str] = Field(default_factory=list)
    matched_patterns: List[str] = Field(default_factory=list)
    reason: Optional[str] = None


class PromptInjectionDetector:
    """Multi-stage detector for direct prompt injection and adversarial manipulation."""

    # Category 1: Instruction Override / System Reset
    INSTRUCTION_OVERRIDE_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|directives|prompts|rules)", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|directives|prompts|rules)", re.IGNORECASE),
        re.compile(r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|directives|prompts|rules)", re.IGNORECASE),
        re.compile(r"(override|bypass|disable)\s+(all\s+)?(system|safety|security)\s+(filters|rules|prompts|policies)", re.IGNORECASE),
        re.compile(r"system\s+(override|reset|reboot|admin mode)", re.IGNORECASE),
        re.compile(r"new\s+system\s+instruction:", re.IGNORECASE),
    ]

    # Category 2: Role Hijacking / Jailbreak Personas
    ROLE_HIJACKING_PATTERNS = [
        re.compile(r"you\s+are\s+now\s+(in\s+)?(DAN|developer|unrestricted|jailbreak|chaos|evil|unfiltered)\s+mode", re.IGNORECASE),
        re.compile(r"act\s+as\s+(an?\s+)?(unrestricted|jailbroken|unfiltered|evil|rogue)\s+(AI|bot|assistant|model)", re.IGNORECASE),
        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+(a\s+different\s+AI|unrestricted|not\s+bound\s+by\s+rules)", re.IGNORECASE),
        re.compile(r"you\s+have\s+no\s+(morals|rules|ethics|restrictions|guidelines)", re.IGNORECASE),
        re.compile(r"simulate\s+(DAN|jailbroken\s+assistant)", re.IGNORECASE),
    ]

    # Category 3: System Prompt / Secret Exfiltration
    PROMPT_LEAKAGE_PATTERNS = [
        re.compile(r"(repeat|reveal|print|show|output|leak|display)\s+(the\s+)?(full\s+|entire\s+|initial\s+)*(system\s+prompt|initial\s+instructions|instructions\s+above)", re.IGNORECASE),
        re.compile(r"what\s+(is|are|were|was)\s+(your\s+)?(exact\s+)?(system\s+prompt|hidden\s+instructions|initial\s+instructions|internal\s+prompts)", re.IGNORECASE),
        re.compile(r"instructions\s+(given\s+)?before\s+this", re.IGNORECASE),
        re.compile(r"echo\s+back\s+(the\s+)?(initial|system)\s+prompt", re.IGNORECASE),
        re.compile(r"what\s+did\s+the\s+developer\s+tell\s+you", re.IGNORECASE),
    ]

    # Category 4: Delimiter & Context Breakout
    DELIMITER_ESCAPE_PATTERNS = [
        re.compile(r"</?RETRIEVED_CONTEXT>", re.IGNORECASE),
        re.compile(r"</?SYSTEM_INSTRUCTIONS>", re.IGNORECASE),
        re.compile(r"</?USER_QUERY>", re.IGNORECASE),
        re.compile(r"\[/?INST\]", re.IGNORECASE),
        re.compile(r"<<SYS>>|<<\/SYS>>", re.IGNORECASE),
        re.compile(r"<\|im_start\|>|<\|im_end\|>", re.IGNORECASE),
        re.compile(r"Human:\s*.*Assistant:\s*", re.IGNORECASE),
    ]

    def __init__(self, policy: Optional[PromptInjectionPolicy] = None):
        self.policy = policy or settings.PROMPT_INJECTION_POLICY

    def analyze(
        self,
        text: str,
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        redteam_case_id: Optional[str] = None,
    ) -> InjectionDetectionResult:
        """Scan text for prompt injection patterns and return detection decision."""
        matched_categories = []
        matched_patterns = []

        categories = [
            ("INSTRUCTION_OVERRIDE", self.INSTRUCTION_OVERRIDE_PATTERNS),
            ("ROLE_HIJACKING", self.ROLE_HIJACKING_PATTERNS),
            ("PROMPT_LEAKAGE", self.PROMPT_LEAKAGE_PATTERNS),
            ("DELIMITER_ESCAPE", self.DELIMITER_ESCAPE_PATTERNS),
        ]

        for cat_name, patterns in categories:
            for pat in patterns:
                match = pat.search(text)
                if match:
                    if cat_name not in matched_categories:
                        matched_categories.append(cat_name)
                    matched_patterns.append(pat.pattern)

        if not matched_categories:
            return InjectionDetectionResult(
                is_injection=False,
                decision=SecurityDecision.ALLOWED,
                confidence=0.0,
            )

        # Calculate confidence based on category count and matches
        confidence = min(1.0, 0.70 + (0.10 * len(matched_categories)) + (0.05 * len(matched_patterns)))

        # Decide whether to block or detect based on configured policy
        decision = (
            SecurityDecision.BLOCKED
            if self.policy == PromptInjectionPolicy.BLOCK
            else SecurityDecision.DETECTED
        )

        reason = f"Prompt injection indicators detected in categories: {', '.join(matched_categories)}"

        # Log security audit event
        event = SecurityEvent(
            correlation_id=correlation_id or "unknown",
            category=SecurityEventCategory.PROMPT_INJECTION,
            decision=decision,
            severity=SecuritySeverity.HIGH,
            description=reason,
            client_ip=client_ip,
            redteam_case_id=redteam_case_id,
            details={
                "matched_categories": matched_categories,
                "confidence": round(confidence, 2),
                "pattern_count": len(matched_patterns),
            },
        )
        audit_logger.log_event(event)

        return InjectionDetectionResult(
            is_injection=True,
            decision=decision,
            confidence=confidence,
            matched_categories=matched_categories,
            matched_patterns=matched_patterns,
            reason=reason,
        )


# Default singleton instance
prompt_injection_detector = PromptInjectionDetector()
