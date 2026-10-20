"""AegisRAG Application Configuration.

Loads environment variables with secure defaults.
Local mock mode is enabled by default with zero cloud dependencies.
"""

from enum import Enum
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProviderType(str, Enum):
    MOCK = "mock"
    BEDROCK = "bedrock"


class EmbeddingProviderType(str, Enum):
    MOCK = "mock"
    BEDROCK = "bedrock"


class HandlingPolicy(str, Enum):
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    ALLOW = "ALLOW"


class PromptInjectionPolicy(str, Enum):
    BLOCK = "BLOCK"
    DETECT_ONLY = "DETECT_ONLY"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General
    APP_NAME: str = "ContextForge"
    APP_VERSION: str = "0.2.0"
    APP_ENV: str = "development"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # LLM & Embedding Providers
    LLM_PROVIDER: LLMProviderType = LLMProviderType.MOCK
    EMBEDDING_PROVIDER: EmbeddingProviderType = EmbeddingProviderType.MOCK
    MOCK_PROVIDER_RESPONSE_LATENCY_MS: int = 20

    # Optional Amazon Bedrock
    AWS_REGION: str = "us-east-1"
    BEDROCK_MODEL_ID: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    BEDROCK_EMBEDDING_MODEL_ID: str = "amazon.titan-embed-text-v2:0"
    BEDROCK_GUARDRAIL_ID: Optional[str] = None
    BEDROCK_GUARDRAIL_VERSION: Optional[str] = None
    BEDROCK_TIMEOUT_SECONDS: float = 30.0
    BEDROCK_MAX_RETRIES: int = 2

    # Ingestion & Document Safety
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    MAX_PDF_PAGES: int = 50
    INGESTION_TIMEOUT_SECONDS: int = 30
    ALLOWED_MIME_TYPES: List[str] = ["application/pdf"]
    CHUNK_SIZE: int = 500
    CHUNK_OVERLAP: int = 100

    # Retrieval
    RETRIEVAL_TOP_K: int = 4
    RETRIEVAL_MIN_SCORE_THRESHOLD: float = 0.25

    # Security & Guardrail Policies
    INPUT_PII_POLICY: HandlingPolicy = HandlingPolicy.REDACT
    RETRIEVAL_PII_POLICY: HandlingPolicy = HandlingPolicy.REDACT
    OUTPUT_PII_POLICY: HandlingPolicy = HandlingPolicy.REDACT
    PROMPT_INJECTION_POLICY: PromptInjectionPolicy = PromptInjectionPolicy.BLOCK

    MAX_INPUT_LENGTH_CHARS: int = 2000
    ENFORCE_GROUNDING_CHECK: bool = True
    ENFORCE_OUTPUT_SANITIZATION: bool = True
    ENFORCE_SAFETY_DISCLAIMERS: bool = True

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 15

    # Audit & Observability
    AUDIT_LOG_FILE: str = "contextforge_security_events.log"
    LOG_LEVEL: str = "INFO"


# Global settings instance
settings = Settings()
