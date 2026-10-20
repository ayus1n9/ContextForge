"""Health and Readiness API Routes.

Provides health checks, system readiness, and provider status.
"""

from fastapi import APIRouter

from backend.app.config import settings
from backend.app.guardrails.bedrock_guardrails import bedrock_guardrails_client
from backend.app.ingestion.provenance import provenance_registry
from backend.app.retrieval.vector_store import vector_store

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Basic service liveness check."""
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
    }


@router.get("/ready")
def readiness_check():
    """Readiness check reporting vector index state and configured providers."""
    return {
        "status": "ready",
        "llm_provider": settings.LLM_PROVIDER.value,
        "embedding_provider": settings.EMBEDDING_PROVIDER.value,
        "indexed_chunks_count": vector_store.count(),
        "registered_documents_count": len(provenance_registry.list_all()),
        "bedrock_guardrails_active": bedrock_guardrails_client.is_configured(),
    }


@router.get("/version")
def version_info():
    """Application version and security profile details."""
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "security_framework": "AegisRAG Defense-in-Depth AI Security",
        "owasp_llm_top_10_version": "2025",
    }
