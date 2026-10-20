"""In-Memory Cosine Vector Store.

Stores text chunks and dense vector embeddings with metadata filtering.
Provides cosine similarity retrieval without external database dependencies.
"""

from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from backend.app.ingestion.chunking import TextChunk


class VectorStore:
    """In-memory cosine similarity vector index."""

    def __init__(self):
        self._chunks: List[TextChunk] = []
        self._embeddings: Optional[np.ndarray] = None  # shape (N, D)

    def add_chunks(
        self,
        chunks: List[TextChunk],
        embeddings: List[List[float]],
    ) -> int:
        """Add chunks and corresponding embeddings to the vector store."""
        if not chunks or not embeddings:
            return 0
        if len(chunks) != len(embeddings):
            raise ValueError("Chunks and embeddings count mismatch")

        new_embeddings = np.array(embeddings, dtype=np.float32)

        # L2-normalize
        norms = np.linalg.norm(new_embeddings, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        new_embeddings = new_embeddings / norms

        if self._embeddings is None:
            self._embeddings = new_embeddings
            self._chunks = list(chunks)
        else:
            self._embeddings = np.vstack([self._embeddings, new_embeddings])
            self._chunks.extend(chunks)

        return len(chunks)

    def search(
        self,
        query_vector: List[float],
        top_k: int = 4,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[TextChunk, float]]:
        """Perform cosine similarity search against indexed chunks."""
        if self._embeddings is None or len(self._chunks) == 0:
            return []

        q_vec = np.array(query_vector, dtype=np.float32)
        q_norm = np.linalg.norm(q_vec)
        if q_norm > 0:
            q_vec = q_vec / q_norm

        # Cosine similarity is the dot product of normalized vectors
        scores = np.dot(self._embeddings, q_vec)

        # Filter candidate indices based on metadata
        candidate_indices = []
        for idx, chunk in enumerate(self._chunks):
            if metadata_filter:
                match = True
                for k, v in metadata_filter.items():
                    if chunk.metadata.get(k) != v:
                        match = False
                        break
                if not match:
                    continue
            candidate_indices.append(idx)

        if not candidate_indices:
            return []

        # Sort candidate indices by descending similarity score
        candidate_scores = [(idx, float(scores[idx])) for idx in candidate_indices]
        candidate_scores.sort(key=lambda x: x[1], reverse=True)

        results = []
        for idx, score in candidate_scores[:top_k]:
            results.append((self._chunks[idx], score))

        return results

    def count(self) -> int:
        return len(self._chunks)

    def clear(self) -> None:
        self._chunks.clear()
        self._embeddings = None


# Default singleton instance
vector_store = VectorStore()
