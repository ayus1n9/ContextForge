"""Embedding Generation Layer.

Provides embedding abstractions:
1. MockLocalEmbeddingProvider: Deterministic n-gram hash vectorizer for local/test execution (100% offline, zero cloud).
2. BedrockTitanEmbeddingProvider: Optional Amazon Bedrock Titan v2 embedding provider.
"""

import hashlib
import json
from abc import ABC, abstractmethod
from typing import List, Optional

import numpy as np

from backend.app.config import settings


class BaseEmbeddingProvider(ABC):
    """Abstract base class for embedding models."""

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Embed a single text string into a normalized float vector."""
        pass

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple text strings."""
        pass


class MockLocalEmbeddingProvider(BaseEmbeddingProvider):
    """Deterministic local embedding provider using term hashing and cosine normalization.

    Generates reproducible 128-dimensional dense vectors without external models.
    """

    def __init__(self, dimension: int = 128):
        self.dimension = dimension

    def embed_text(self, text: str) -> List[float]:
        vector = np.zeros(self.dimension, dtype=np.float32)
        words = text.lower().split()
        if not words:
            return vector.tolist()

        for word in words:
            # Deterministic hash to dimension index (non-cryptographic feature hashing)
            h = int(hashlib.md5(word.encode("utf-8"), usedforsecurity=False).hexdigest(), 16)
            idx = h % self.dimension
            sign = 1.0 if (h % 2 == 0) else -1.0
            vector[idx] += sign

        # L2 normalization
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        return vector.tolist()

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed_text(t) for t in texts]


class BedrockTitanEmbeddingProvider(BaseEmbeddingProvider):
    """Optional Amazon Bedrock Titan Text Embeddings provider."""

    def __init__(
        self,
        model_id: Optional[str] = None,
        region_name: Optional[str] = None,
    ):
        self.model_id = model_id or settings.BEDROCK_EMBEDDING_MODEL_ID
        self.region_name = region_name or settings.AWS_REGION
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("bedrock-runtime", region_name=self.region_name)
        return self._client

    def embed_text(self, text: str) -> List[float]:
        client = self._get_client()
        body = json.dumps({"inputText": text})
        response = client.invoke_model(
            modelId=self.model_id,
            body=body,
            contentType="application/json",
            accept="application/json",
        )
        response_body = json.loads(response["body"].read())
        return response_body["embedding"]

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed_text(t) for t in texts]


def get_embedding_provider() -> BaseEmbeddingProvider:
    """Factory function to instantiate the configured embedding provider."""
    if settings.EMBEDDING_PROVIDER == "bedrock":
        return BedrockTitanEmbeddingProvider()
    return MockLocalEmbeddingProvider()


# Default global instance
embedding_provider = get_embedding_provider()
