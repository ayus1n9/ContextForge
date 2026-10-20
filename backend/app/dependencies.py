"""FastAPI Dependency Injection Providers.

Provides initialized instances of configuration, guardrail pipeline,
retriever, and access controls for API routes.
"""

from typing import Optional

from fastapi import Header, Request

from backend.app.guardrails.pipeline import GuardrailPipeline, guardrail_pipeline
from backend.app.security.access_control import DocumentClassification, UserContext


def get_guardrail_pipeline() -> GuardrailPipeline:
    """Dependency provider for the main guardrail pipeline."""
    return guardrail_pipeline


def get_current_user_context(
    request: Request,
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_roles: Optional[str] = Header(None, alias="X-User-Roles"),
    x_user_clearance: Optional[str] = Header(None, alias="X-User-Clearance"),
) -> UserContext:
    """Extract authenticated or anonymous user context from headers."""
    user_id = x_user_id or "anonymous_user"
    roles = [r.strip() for r in x_user_roles.split(",")] if x_user_roles else ["viewer"]

    clearance = DocumentClassification.PUBLIC
    if x_user_clearance:
        try:
            clearance = DocumentClassification(x_user_clearance.upper())
        except ValueError:
            clearance = DocumentClassification.PUBLIC

    return UserContext(user_id=user_id, roles=roles, clearance=clearance)
