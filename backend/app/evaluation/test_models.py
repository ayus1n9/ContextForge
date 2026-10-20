"""Red-Team Adversarial Test Models.

Data contracts for repeatable security evaluation cases, test executions,
and structured scoring reports.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.app.observability.security_events import SecurityDecision


class AttackCategory(str, Enum):
    DIRECT_PROMPT_INJECTION = "DIRECT_PROMPT_INJECTION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    PII_AND_SECRET_DISCLOSURE = "PII_AND_SECRET_DISCLOSURE"  # nosec B105
    RETRIEVAL_AUTHORIZATION = "RETRIEVAL_AUTHORIZATION"
    DOCUMENT_POISONING = "DOCUMENT_POISONING"
    OUTPUT_HANDLING = "OUTPUT_HANDLING"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    ERROR_HANDLING = "ERROR_HANDLING"
    BENIGN_CONTROL = "BENIGN_CONTROL"


class RedTeamTestCase(BaseModel):
    case_id: str
    category: AttackCategory
    threat_name: str
    description: str
    input_prompt: str
    expected_decision: SecurityDecision  # BLOCKED for attacks, ALLOWED for benign
    user_roles: List[str] = Field(default_factory=lambda: ["viewer"])
    user_clearance: str = "PUBLIC"
    document_fixture: Optional[str] = None
    notes: Optional[str] = None


class RedTeamExecutionResult(BaseModel):
    case_id: str
    category: AttackCategory
    threat_name: str
    expected_decision: SecurityDecision
    actual_decision: SecurityDecision
    status: str  # BLOCKED, DETECTED, ALLOWED, FAILED, ERROR, NOT_TESTED
    passed: bool
    evidence: str
    latency_ms: float
    details: Dict[str, Any] = Field(default_factory=dict)


class RedTeamSuiteReport(BaseModel):
    suite_name: str
    timestamp: str
    total_executed: int = 0
    total_passed: int = 0
    total_failed: int = 0
    total_errors: int = 0
    attacks_blocked: int = 0
    attacks_detected_only: int = 0
    attacks_allowed_failure: int = 0
    benign_allowed: int = 0
    benign_false_positives: int = 0
    attack_blocking_rate_pct: float = 0.0
    false_positive_rate_pct: float = 0.0
    results: List[RedTeamExecutionResult] = Field(default_factory=list)
