"""Security Audit and Policy Inspection API Routes.

Allows authorized monitoring of sanitized security events and active guardrail policies.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query

from backend.app.dependencies import get_current_user_context
from backend.app.guardrails.policy import GuardrailPolicy, default_guardrail_policy
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import SecurityEvent
from backend.app.security.access_control import UserContext

router = APIRouter(prefix="/security", tags=["Security & Observability"])


@router.get("/events", response_model=List[SecurityEvent])
def get_security_events(
    limit: int = Query(50, ge=1, le=500),
    category: Optional[str] = Query(None),
    correlation_id: Optional[str] = Query(None),
    user: UserContext = Depends(get_current_user_context),
):
    """Retrieve sanitized security events from the in-memory audit store."""
    return audit_logger.get_recent_events(
        limit=limit, category=category, correlation_id=correlation_id
    )


@router.get("/policy", response_model=GuardrailPolicy)
def get_security_policy(user: UserContext = Depends(get_current_user_context)):
    """Inspect active security and guardrail policy configuration."""
    return default_guardrail_policy
