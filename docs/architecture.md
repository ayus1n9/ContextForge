# AegisRAG System Architecture

AegisRAG is a security-focused Retrieval-Augmented Generation (RAG) system engineered for high-assurance document question answering on technical reference manuals.

---

## Architecture Overview

```
                                      +------------------------------------+
                                      |            API Layer               |
                                      |   FastAPI + Security Middlewares   |
                                      |  (CORS, CSP, Size Limits, Headers) |
                                      +-----------------+------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |        Input Security Gate         |
                                      |  - Sliding-Window Rate Limiter     |
                                      |  - String/Encoding Validator       |
                                      |  - Prompt Injection Detector       |
                                      |  - Input PII Redactor (BLOCK/REDACT)|
                                      +-----------------+------------------+
                                                        |
                                                        v
+-------------------------------+     +------------------------------------+
|     Document Ingestion        |     |       Retrieval & Access Core      |
|  - Magic Bytes Check (%PDF-)  |     |  - Dense Cosine Vector Index       |
|  - Exploit Scanner (/Launch)  |---> |  - Minimum Relevance Threshold     |
|  - Safe PyPDF Text Extractor  |     |  - RBAC & Document Clearance ACL   |
|  - Provenance Registry        |     |  - Context PII Sanitizer           |
+-------------------------------+     +-----------------+------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |        Prompt Boundary Engine      |
                                      |  - Untrusted Context Encapsulation |
                                      |  - Instruction Hierarchy Rules     |
                                      |  - Strict Citation Formatting Directives
                                      +-----------------+------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |         LLM Provider Layer         |
                                      |  - Deterministic Mock Provider     |
                                      |  - Optional Amazon Bedrock Converse|
                                      +-----------------+------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |        Output Security Gate        |
                                      |  - Output PII Redaction            |
                                      |  - Canary / Secret Leakage Filter  |
                                      |  - XSS HTML Escaping Filter        |
                                      |  - Grounding & Citation Verifier   |
                                      |  - High-Stakes Safety Disclaimer   |
                                      +-----------------+------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |         Structured Response        |
                                      |  Answer + Citations + Audit Report |
                                      +------------------------------------+
```

---

## Core Components

### 1. Ingestion Engine (`backend/app/ingestion/`)
- **Document Validator**: Inspects binary files for magic header `%PDF-`, size bounds (max 10MB), and scans byte stream for active executable exploit tags (`/Launch`, `/JavaScript`, `/SubmitForm`, `/ImportData`).
- **Safe PDF Parser**: Extracts text page-by-page using `pypdf` under strict page caps (max 50 pages) and timeout limits.
- **Provenance Registry**: Calculates SHA-256 content hashes, cataloging document metadata (publisher, title, source URL, page count, publication date) and detecting duplicate re-ingestion.
- **Chunker**: Splits text into sliding windows (500 chars, 100 char overlap) while preserving 1-indexed page numbers and document metadata.

### 2. Retrieval & Vector Store (`backend/app/retrieval/`)
- **Embeddings**: Abstract interface supporting local deterministic n-gram feature hashing (`MockLocalEmbeddingProvider`) and optional `BedrockTitanEmbeddingProvider`.
- **Vector Store**: In-memory cosine similarity search engine with metadata filtering.
- **Retriever**: Combines semantic similarity with a minimum score threshold and backend access control filtering.

### 3. Guardrails Engine (`backend/app/guardrails/`)
- **Input Gate**: Pre-retrieval validation (null-bytes, character limits, rate limiting).
- **Injection Defense**: Regex and heuristic pattern matching across instruction overrides, roleplay hijacking, prompt leakage, and delimiter escapes.
- **PII Protection**: Detects and redacts Emails, Phone numbers, SSNs, Credit Cards (Luhn verified), and Canary secrets.
- **Output Gate**: Neutralizes XSS markup, strips Canary tokens, validates citations, and appends official safety notices.

### 4. LLM Provider Abstraction (`backend/app/llm/`)
- **Mock Provider**: Zero-cloud deterministic model simulator synthesizing factual answers from retrieved chunks and refusing adversarial overrides.
- **Bedrock Provider**: Boto3 Converse API client with token limits, retries, and timeouts without hardcoded credentials.
