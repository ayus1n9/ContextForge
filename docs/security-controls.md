# AegisRAG Security Controls Specification

This document details the layered defense controls implemented in AegisRAG.

---

## 1. Input Validation Controls

| Control ID | Name | Enforcement Layer | Behavior |
| :--- | :--- | :--- | :--- |
| **INP-01** | Length Bound Check | `backend/app/security/input_validation.py` | Rejects requests where query string exceeds `MAX_INPUT_LENGTH_CHARS` (2,000 characters). Returns HTTP 400. |
| **INP-02** | Null Byte Neutralization | `backend/app/security/input_validation.py` | Scans for binary null characters (`\x00`) used in file extension truncation and buffer manipulation; rejects request if found. |
| **INP-03** | Control Character Filtering | `backend/app/security/input_validation.py` | Strips or rejects ASCII control characters (`ord < 32` excluding `\t`, `\n`, `\r`) to prevent terminal and terminal escape injections. |
| **INP-04** | Client Rate Limiting | `backend/app/security/rate_limits.py` | Sliding-window algorithm capping clients at 60 requests/min and maximum burst of 15 requests/5s per IP. Returns HTTP 429. |

---

## 2. Prompt Injection Defense Controls

| Control ID | Name | Enforcement Layer | Behavior |
| :--- | :--- | :--- | :--- |
| **INJ-01** | Instruction Override Detection | `backend/app/security/prompt_injection.py` | Scans queries for system override phrases (`ignore previous instructions`, `disregard rules`, `system reset`). Blocks request and logs audit event. |
| **INJ-02** | Persona Hijacking Detection | `backend/app/security/prompt_injection.py` | Detects jailbreak personas (`DAN mode`, `unrestricted AI`, `developer mode`). Blocks request. |
| **INJ-03** | Delimiter Escape Defense | `backend/app/security/prompt_injection.py` | Detects spoofed boundary tags (`</RETRIEVED_CONTEXT>`, `[INST]`, `<<SYS>>`). Blocks request. |
| **INJ-04** | Prompt Exfiltration Defense | `backend/app/security/prompt_injection.py` | Detects attempts to print internal system prompts or hidden instructions. Blocks request. |
| **INJ-05** | Indirect Injection Isolation | `backend/app/llm/prompts.py` | Retrieved passages are encapsulated within untrusted `<RETRIEVED_CONTEXT>` tags with explicit instruction hierarchy directing the model to treat passages solely as passive data. |

---

## 3. PII & Sensitive Information Protection

| Control ID | Name | Categories Covered | Handling Policy |
| :--- | :--- | :--- | :--- |
| **PII-01** | Email Redaction | RFC 5322 compatible email address pattern | Replaced with `[REDACTED_EMAIL]` |
| **PII-02** | Phone Redaction | US and international phone formats | Replaced with `[REDACTED_PHONE]` |
| **PII-03** | SSN Redaction | US Social Security Numbers (`XXX-XX-XXXX`) | Replaced with `[REDACTED_SSN]` |
| **PII-04** | Credit Card Defense | 13-19 digit cards validated via Luhn algorithm | Replaced with `[REDACTED_CARD]` |
| **PII-05** | Secret Key Redaction | Synthetic Canary tokens (`CANARY-*`, `AEGIS_SECRET_*`, API keys) | Replaced with `[REDACTED_SECRET]` |
| **PII-06** | Audit Log Scrubbing | All logged JSON objects | Automatically scrubs Canary tokens and PII before writing to disk sinks. |

---

## 4. Document Ingestion Security Controls

| Control ID | Name | Enforcement Layer | Behavior |
| :--- | :--- | :--- | :--- |
| **DOC-01** | Magic Bytes Verification | `backend/app/ingestion/document_validation.py` | Verifies file starts with `%PDF-`. |
| **DOC-02** | Active Tag Rejection | `backend/app/ingestion/document_validation.py` | Scans raw PDF binary for `/Launch`, `/JavaScript`, `/JS`, `/SubmitForm`, `/ImportData`, and `/RichMedia`. Rejects file with HTTP 400. |
| **DOC-03** | Page Count Limiting | `backend/app/ingestion/pdf_parser.py` | Rejects PDFs exceeding 50 pages to prevent parser denial of service. |
| **DOC-04** | SSRF Safe Fetcher | `backend/app/ingestion/ingestion_pipeline.py` | Restricts remote URLs to HTTPS. Resolves DNS and blocks private IPs (RFC 1918), loopback, link-local, and AWS cloud metadata (`169.254.169.254`). |
| **DOC-05** | SHA-256 Deduplication | `backend/app/ingestion/provenance.py` | Generates cryptographic hash of file bytes; skips redundant re-ingestion. |

---

## 5. Output Security & Grounding Controls

| Control ID | Name | Enforcement Layer | Behavior |
| :--- | :--- | :--- | :--- |
| **OUT-01** | XSS Script Escaping | `backend/app/security/output_filter.py` | Scans output for `<script>`, `<iframe>`, `<svg>`, and `javascript:`; escapes HTML entities to neutralize execution. |
| **OUT-02** | Canary Secret Leak Filter | `backend/app/security/output_filter.py` | Blocks response if internal Canary secrets or AWS keys appear in generated text. |
| **OUT-03** | Citation Validation | `backend/app/security/grounding.py` | Validates that cited documents and page numbers exist in retrieved chunks. Blocks fabricated citations. |
| **OUT-04** | Insufficient Evidence Policy | `backend/app/security/grounding.py` | Requires explicit abstention when retrieved context lacks factual evidence. |
| **OUT-05** | High-Stakes Aviation Disclaimer | `backend/app/security/output_filter.py` | Appends mandatory educational notice warning users not to use answers for operational flight safety. |
