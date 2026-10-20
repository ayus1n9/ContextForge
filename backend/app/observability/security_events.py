"""Structured Security Event Models.

Tracks security events across the entire RAG pipeline with sanitized metadata.
Never logs raw secrets, Canary tokens, or unredacted PII.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class SecurityEventCategory(str, Enum):
    INPUT_VALIDATION = "INPUT_VALIDATION"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    PII_DETECTED = "PII_DETECTED"
    RETRIEVAL_AUTHORIZATION = "RETRIEVAL_AUTHORIZATION"
    OUTPUT_VIOLATION = "OUTPUT_VIOLATION"
    GROUNDING_FAILURE = "GROUNDING_FAILURE"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    DOCUMENT_SAFETY = "DOCUMENT_SAFETY"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    SYSTEM = "SYSTEM"


class SecurityDecision(str, Enum):
    BLOCKED = "BLOCKED"
    DETECTED = "DETECTED"
    REDACTED = "REDACTED"
    ALLOWED = "ALLOWED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    NOT_TESTED = "NOT_TESTED"


class SecuritySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    category: SecurityEventCategory
    decision: SecurityDecision
    severity: SecuritySeverity = SecuritySeverity.MEDIUM
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    client_ip: Optional[str] = None
    redteam_case_id: Optional[str] = None
