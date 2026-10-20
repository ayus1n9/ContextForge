# ContextForge Data Flow Architecture

This document describes data flow paths across trust boundaries in ContextForge.

---

## 1. Document Ingestion Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor Admin as User / Engineer
    participant Ingress as FastAPI (/documents/upload)
    participant Validator as DocumentValidator
    participant Parser as SafePDFParser
    participant Provenance as ProvenanceRegistry
    participant Chunker as TextChunker
    participant Embedder as EmbeddingProvider
    participant VStore as VectorStore
    participant Auditor as SecurityAuditLogger

    Admin->>Ingress: Upload PDF File + Metadata
    Ingress->>Validator: Validate Magic Bytes (%PDF-) & Scan Active Tags (/Launch)
    alt Malicious PDF detected
        Validator->>Auditor: Log DOCUMENT_SAFETY BLOCKED
        Validator-->>Ingress: Reject with HTTP 400
        Ingress-->>Admin: Security Error
    else Valid PDF
        Validator->>Parser: Extract text page-by-page
        Parser->>Provenance: Register SHA-256 hash & metadata
        Parser->>Chunker: Split pages into sliding text chunks
        Chunker->>Embedder: Generate vector embeddings
        Embedder->>VStore: Index chunks and normalized vectors
        Ingress->>Auditor: Log DOCUMENT_SAFETY ALLOWED
        Ingress-->>Admin: Return HTTP 201 Created
    end
```

---

## 2. RAG Query Execution Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Client
    participant API as FastAPI (/chat/query)
    participant RateLimit as SlidingWindowRateLimiter
    participant InpVal as InputValidator
    participant InjDet as PromptInjectionDetector
    participant PIIRedact as PIIRedactor
    participant Retriever as SecureRetriever
    participant ACL as AccessControlEnforcer
    participant VStore as VectorStore
    participant LLM as LLMProvider (Mock / Bedrock)
    participant OutFilter as OutputFilter
    participant Grounding as GroundingEvaluator
    participant Auditor as SecurityAuditLogger

    User->>API: POST /chat/query (Prompt + User Headers)
    API->>RateLimit: Check rate limits for client IP
    API->>InpVal: Check string length, null bytes, control chars
    API->>InjDet: Scan for direct injection / jailbreaks
    alt Prompt Injection Detected
        InjDet->>Auditor: Log PROMPT_INJECTION BLOCKED
        API-->>User: Security Notice: Request Blocked
    else Clean Prompt
        API->>PIIRedact: Scrub input PII (Email, Phone, SSN, Secrets)
        API->>Retriever: Retrieve relevant chunks
        Retriever->>VStore: Cosine similarity search (Top-K)
        VStore-->>Retriever: Candidate Chunks
        Retriever->>ACL: Enforce User Clearance vs Doc Classification
        ACL-->>Retriever: Authorized Chunks Only
        API->>PIIRedact: Scrub retrieved chunk PII
        API->>LLM: Generate Answer with <RETRIEVED_CONTEXT>
        LLM-->>API: Raw Model Output
        API->>OutFilter: Neutralize XSS markup & check Canary leakage
        API->>PIIRedact: Scrub output PII
        API->>Grounding: Verify factual citations & support
        alt Fabricated Citation Detected
            Grounding->>Auditor: Log GROUNDING_FAILURE BLOCKED
            API-->>User: Security Notice: Grounding Failure
        else Verified Grounded
            OutFilter->>API: Attach Aviation Safety Disclaimer
            API-->>User: Return Answer + Valid Citations + Security Report
        end
    end
```
