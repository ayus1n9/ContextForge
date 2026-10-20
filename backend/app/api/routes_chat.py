"""Chat and Question-Answering API Routes.

Exposes the secure RAG query interface protected by the multi-layered guardrail pipeline.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from backend.app.dependencies import get_current_user_context, get_guardrail_pipeline
from backend.app.guardrails.pipeline import (
    GuardrailPipeline,
    GuardrailPipelineResponse,
)
from backend.app.security.access_control import UserContext

router = APIRouter(prefix="/chat", tags=["Chat & RAG"])


class ChatQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000, description="User question or prompt")
    metadata_filter: Optional[Dict[str, Any]] = Field(None, description="Optional metadata filter")
    redteam_case_id: Optional[str] = Field(None, description="Optional red-team evaluation case ID")


@router.post("/query", response_model=GuardrailPipelineResponse)
def query_rag(
    request: Request,
    payload: ChatQueryRequest,
    pipeline: GuardrailPipeline = Depends(get_guardrail_pipeline),
    user: UserContext = Depends(get_current_user_context),
):
    """Execute a grounded RAG question-answering query under full guardrails."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    response = pipeline.process_query(
        query=payload.query,
        user=user,
        client_ip=client_ip,
        redteam_case_id=payload.redteam_case_id,
        metadata_filter=payload.metadata_filter,
    )
    return response
