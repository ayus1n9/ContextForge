"""Secure Document Retriever.

Coordinates embedding generation, vector similarity search,
relevance thresholding, and authorization filtering.
Enforces security decisions before content enters LLM context.
"""

from typing import Any, Dict, List, Optional

from backend.app.config import settings
from backend.app.retrieval.embeddings import BaseEmbeddingProvider, embedding_provider
from backend.app.retrieval.vector_store import VectorStore, vector_store
from backend.app.security.access_control import (
    AccessControlEnforcer,
    UserContext,
    access_control,
)


class Retriever:
    """Secure retriever with authorization and relevance controls."""

    def __init__(
        self,
        store: Optional[VectorStore] = None,
        embedder: Optional[BaseEmbeddingProvider] = None,
        acl: Optional[AccessControlEnforcer] = None,
        min_score: Optional[float] = None,
        top_k: Optional[int] = None,
    ):
        self.store = store or vector_store
        self.embedder = embedder or embedding_provider
        self.acl = acl or access_control
        self.min_score = min_score or settings.RETRIEVAL_MIN_SCORE_THRESHOLD
        self.top_k = top_k or settings.RETRIEVAL_TOP_K

    def retrieve(
        self,
        query: str,
        user: Optional[UserContext] = None,
        metadata_filter: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve authorized relevant chunks for the user's query."""
        user_ctx = user or UserContext()

        # 1. Embed query
        query_vector = self.embedder.embed_text(query)

        # 2. Search vector store
        raw_matches = self.store.search(
            query_vector=query_vector,
            top_k=self.top_k * 2,  # Fetch extra candidates to account for authorization filtering
            metadata_filter=metadata_filter,
        )

        # 3. Filter by minimum relevance threshold
        relevant_chunks: List[Dict[str, Any]] = []
        for chunk, score in raw_matches:
            if score >= self.min_score:
                chunk_dict = {
                    "chunk_id": chunk.chunk_id,
                    "text": chunk.text,
                    "score": round(score, 4),
                    "metadata": chunk.metadata,
                }
                relevant_chunks.append(chunk_dict)

        # 4. Enforce backend retrieval access control
        authorized_chunks = self.acl.filter_chunks(
            chunks=relevant_chunks,
            user=user_ctx,
            correlation_id=correlation_id,
            client_ip=client_ip,
        )

        return authorized_chunks[:self.top_k]


# Default singleton instance
retriever = Retriever()
