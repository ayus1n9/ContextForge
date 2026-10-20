# ContextForge Threat Model and Security Architecture

## 1. Overview & Trust Boundaries

ContextForge is designed under the assumption of **Zero Trust for all external inputs**:
- **Untrusted Zone 1 (User Queries)**: Direct user prompts may contain malicious injection attacks, jailbreak payloads, Canary exfiltration attempts, PII, or resource-exhaustion payloads.
- **Untrusted Zone 2 (External Documents)**: PDF files ingested from local or remote sources may contain active executable tags (`/Launch`, `/JavaScript`), malformed streams, or indirect prompt injection instructions.
- **Untrusted Zone 3 (Model Generation)**: Model responses may hallucinate false facts, leak confidential credentials, or generate XSS markup.
- **Trusted Zone (Application Security Core)**: Security enforcement logic, input validation, regex/heuristic pattern matching, PII redaction, access control, and citation grounding run exclusively within backend application code, never delegated to natural language model instructions.

```
+-----------------------------------------------------------------------------------------+
|                                    TRUST BOUNDARY                                       |
|                                                                                         |
|  [Untrusted User Query] ----> (Input Validation & Rate Limiter)                         |
|                                        |                                                |
|                                        v                                                |
|                            (Prompt Injection Detector)                                  |
|                                        |                                                |
|                                        v                                                |
|                              (PII Redaction Engine)                                     |
|                                        |                                                |
|  [Untrusted PDF Corpus]               v                                                 |
|          |                 (Authorized Vector Retrieval)                                |
|          v                             |                                                |
|  (PDF Security Scan)                   v                                                |
|  (Active Tag Rejection) ---> <RETRIEVED_CONTEXT> (Isolated Untrusted Container)         |
|                                        |                                                |
|                                        v                                                |
|                             [LLM / Bedrock Provider]                                    |
|                                        |                                                |
|                                        v                                                |
|                       (Output Filter: Canary & XSS Sanitizer)                           |
|                                        |                                                |
|                                        v                                                |
|                         (Grounding & Citation Validator)                                |
|                                        |                                                |
|                                        v                                                |
|                            [Sanitized Grounded Answer]                                  |
+-----------------------------------------------------------------------------------------+
```

---

## 2. STRIDE Threat Analysis

| Threat Category | System Vulnerability | Implemented Defense Controls | Residual Risk |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates privileged roles or spoof delimiter tags (`</RETRIEVED_CONTEXT>`). | Delimiter escape pattern detector rejects structural injection; role context is cryptographically derived from trusted request headers. | Misconfigured ingress headers if deployed without reverse proxy authentication. |
| **Tampering** | Ingesting poisoned PDF documents with malicious active scripts or altered text. | Magic bytes validation (`%PDF-`), active tag scanning (`/Launch`, `/JavaScript`), SHA-256 hash deduplication. | Semantic poisoning with subtle factual inaccuracies cannot be completely detected by byte analysis. |
| **Repudiation** | Malicious users denying injection or exfiltration attempts. | Structured JSON Lines audit logging with unique UUID correlation IDs and client IP attribution. | Log tampering if audit files are not forwarded to an immutable write-once log sink in production. |
| **Information Disclosure** | Leakage of PII, internal Canary tokens, API keys, or system prompt instructions. | Multi-tier PII detector (Emails, Phone, SSN, Credit Cards with Luhn check, Canary secrets), output secret filter. | Novel zero-day secret formats or non-standard PII syntax that evade regex patterns. |
| **Denial of Service** | Oversized payloads, decompression bombs, or high-volume automated query bursts. | Character length caps (2000 chars), sliding window rate limiter per IP, PDF page count limits (50 pages max). | Distributed denial of service (DDoS) across large botnets requires upstream WAF/CDN rate limiting. |
| **Elevation of Privilege** | Normal viewer accessing restricted documents or executing arbitrary tools. | Zero autonomous tools; document-level access control enforced in Python retriever logic before passing chunks to LLM. | Misassigned role attributes in user identity store. |

---

## 3. OWASP Top 10 for LLM Applications (2025) Control Matrix

### LLM01: Prompt Injection
- **Relevant Threats**: Direct jailbreaks, role hijacking ("DAN mode"), instruction override, and indirect prompt injection through poisoned technical documentation.
- **Implemented Controls**:
  - `backend/app/security/prompt_injection.py`: Deterministic multi-stage regex and heuristic detection covering instruction overrides, roleplay personas, and boundary breakout.
  - `backend/app/llm/prompts.py`: Structural boundary tags (`<RETRIEVED_CONTEXT>`) explicitly commanding the model to treat retrieved passages as passive reference data.
- **Verification Tests**: `test_prompt_injection.py`, `test_owasp_llm_top10.py::test_llm01_prompt_injection_direct`, red-team suite cases `INJ-001` through `INJ-005` and `IND-001`.
- **Residual Risks**: Novel linguistic paraphrasing and zero-shot obfuscation techniques can theoretically evade keyword signatures; prompt injection cannot be 100% eliminated.

### LLM02: Sensitive Information Disclosure
- **Relevant Threats**: Accidental output of PII (emails, phone numbers, SSNs, credit cards) or Canary secrets in responses.
- **Implemented Controls**:
  - `backend/app/security/pii_redaction.py`: Policy-driven detection and redaction supporting `BLOCK`, `REDACT`, and `ALLOW` across user input, retrieved context, and generated output. Luhn algorithm checksum for credit cards.
  - `backend/app/observability/audit_logging.py`: Automated scrubber ensuring no Canary tokens or raw PII are stored in audit logs.
- **Verification Tests**: `test_pii_redaction.py`, `test_owasp_llm_top10.py::test_llm02_sensitive_information_disclosure`, red-team suite cases `PII-001` through `PII-004`.
- **Residual Risks**: Unstructured personal names and non-standard international identifiers may evade regex matching without large contextual NLP models.

### LLM03: Supply Chain
- **Relevant Threats**: Vulnerable third-party dependencies, malicious pip packages, or unverified document sources.
- **Implemented Controls**:
  - Document provenance registry (`backend/app/ingestion/provenance.py`) tracking publishers, original URLs, and SHA-256 hashes.
  - Automated dependency vulnerability scanning with `pip-audit` in CI/CD pipeline.
  - Static security analysis with `bandit`.
- **Verification Tests**: Automated GitHub Actions CI workflow, `pip-audit` zero-vulnerability check.
- **Residual Risks**: Upstream compromises in foundation models or direct PyPI repository compromises before advisory publication.

### LLM04: Data and Model Poisoning
- **Relevant Threats**: PDFs with weaponized payloads, corrupted PDF streams, or adversarial text designed to poison vector search.
- **Implemented Controls**:
  - `backend/app/ingestion/document_validation.py`: Active content tag scanner blocking `/Launch`, `/JavaScript`, `/JS`, `/SubmitForm`, and `/ImportData`.
  - Cryptographic SHA-256 deduplication preventing identical document re-injection.
- **Verification Tests**: `test_ingestion_and_pdf.py::test_reject_malicious_launch_action`, `test_owasp_llm_top10.py::test_llm04_data_poisoning_malicious_pdf`.
- **Residual Risks**: Plausible-sounding false information written into valid PDF text streams requires human subject-matter review.

### LLM05: Improper Output Handling
- **Relevant Threats**: Cross-site scripting (XSS), script injection in web UI, or markdown escape sequences returned by model.
- **Implemented Controls**:
  - `backend/app/security/output_filter.py`: Regex-based XSS detector and automatic HTML entity escaping (`html.escape`).
  - Strict Content-Security-Policy (CSP) headers in `backend/app/main.py`.
- **Verification Tests**: `test_output_filter.py::test_xss_script_neutralized`, `test_owasp_llm_top10.py::test_llm05_improper_output_handling`.
- **Residual Risks**: Complex Markdown rendering engines with novel parser edge cases.

### LLM06: Excessive Agency
- **Relevant Threats**: LLM executing shell commands, modifying databases, or taking autonomous actions without human authorization.
- **Implemented Controls**:
  - The application provides **zero autonomous tools or execution agents**. The model interface is strictly read-only question answering.
  - Retrieval authorization is enforced in application code prior to model invocation.
- **Verification Tests**: `test_owasp_llm_top10.py::test_llm06_excessive_agency`.
- **Residual Risks**: None within current system boundary.

### LLM07: System Prompt Leakage
- **Relevant Threats**: Adversary prompting the model to reveal internal prompts, hidden instructions, or system keys.
- **Implemented Controls**:
  - `PROMPT_LEAKAGE_PATTERNS` in `prompt_injection.py` specifically blocks prompt extraction attempts.
  - Prompts do not store API keys, passwords, or sensitive authorization secrets.
- **Verification Tests**: `test_prompt_injection.py::test_system_prompt_leakage_blocked`, `test_owasp_llm_top10.py::test_llm07_system_prompt_leakage`.
- **Residual Risks**: Multi-step conversational extraction or sophisticated indirect framing.

### LLM08: Vector and Embedding Weaknesses
- **Relevant Threats**: Unauthorized retrieval of sensitive chunks, vector injection, or metadata filter manipulation.
- **Implemented Controls**:
  - `backend/app/security/access_control.py`: Role-Based Access Control (RBAC) and document classification filters (`PUBLIC`, `INTERNAL`, `RESTRICTED`) applied in Python before chunks enter the LLM prompt.
  - Source validator checks chunk integrity against provenance registry.
- **Verification Tests**: `test_access_control.py`, `test_owasp_llm_top10.py::test_llm08_vector_and_embedding_weaknesses`.
- **Residual Risks**: Embedding collision or vector inversion attacks on high-dimensional vectors.

### LLM09: Misinformation
- **Relevant Threats**: Hallucinated aviation facts, fabricated citations, or confidently incorrect technical procedures.
- **Implemented Controls**:
  - `backend/app/security/grounding.py`: Contextual grounding evaluator and citation validator.
  - Insufficient evidence abstention: System explicitly states when verified reference documents lack proof.
  - Mandatory aviation safety disclaimer appended to technical responses.
- **Verification Tests**: `test_grounding.py`, `test_owasp_llm_top10.py::test_llm09_misinformation_and_grounding`.
- **Residual Risks**: Subtly misquoted facts that pass term-overlap thresholds.

### LLM10: Unbounded Consumption
- **Relevant Threats**: Denial of service through oversized prompts, resource-heavy PDF parsing, or rapid-fire API flooding.
- **Implemented Controls**:
  - `settings.MAX_INPUT_LENGTH_CHARS = 2000` enforced at API intake.
  - `settings.MAX_PDF_PAGES = 50` and `MAX_UPLOAD_SIZE_BYTES = 10MB`.
  - In-memory sliding window rate limiter (`RATE_LIMIT_PER_MINUTE = 60`, `BURST = 15`).
  - Request entity size middleware rejecting HTTP bodies > 15MB.
- **Verification Tests**: `test_rate_limits.py`, `test_input_validation.py::test_oversized_query_rejected`, `test_owasp_llm_top10.py::test_llm10_unbounded_consumption`.
- **Residual Risks**: Memory consumption under sustained high concurrency requires horizontal scaling and external reverse proxy rate limiting.
