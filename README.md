# ContextForge — Secure Retrieval-Augmented Generation Application with AI Security Guardrails

[![CI](https://github.com/ayus1n9/ContextForge/actions/workflows/ci.yml/badge.svg)](https://github.com/ayus1n9/ContextForge/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-green.svg)](https://github.com/PyCQA/bandit)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A high-assurance, security-focused Retrieval-Augmented Generation (RAG) system engineered for technical document question answering on official FAA and NASA aviation manuals. ContextForge demonstrates practical defense-in-depth AI security engineering: multi-layered prompt-injection defenses, policy-driven PII redaction, source-grounded citation enforcement, and automated adversarial red-team evaluation.

---

## Table of Contents
1. [Problem Statement](#problem-statement)
2. [Key Security Features](#key-security-features)
3. [System Architecture](#system-architecture)
4. [Technology Stack](#technology-stack)
5. [Project Structure](#project-structure)
6. [Prerequisites & Local Installation](#prerequisites--local-installation)
7. [Environment Configuration](#environment-configuration)
8. [Public PDF Corpus & Ingestion](#public-pdf-corpus--ingestion)
9. [RAG Pipeline & Security Boundaries](#rag-pipeline--security-boundaries)
10. [Prompt-Injection Defenses](#prompt-injection-defenses)
11. [PII Protection & Redaction](#pii-protection--redaction)
12. [Output Security & Grounding](#output-security--grounding)
13. [Adversarial Red-Team Suite & Evaluation](#adversarial-red-team-suite--evaluation)
14. [Actual Evaluation Results](#actual-evaluation-results)
15. [OWASP Top 10 for LLM Applications (2025)](#owasp-top-10-for-llm-applications-2025)
16. [Optional Amazon Bedrock Integration](#optional-amazon-bedrock-integration)
17. [Docker & Container Hardening](#docker--container-hardening)
18. [CI/CD & DevSecOps Checks](#cicd--devsecops-checks)
19. [Limitations & Operational Safety](#limitations--operational-safety)

---

## Problem Statement

Standard RAG implementations naively concatenate untrusted user inputs with untrusted retrieved text into prompt templates. This exposes applications to critical vulnerabilities:
- **Direct Prompt Injection & Jailbreaks**: Attacker prompts hijack assistant persona or override application rules.
- **Indirect Prompt Injection**: Malicious instructions embedded in documents hijack model context upon retrieval.
- **Data & Credential Exfiltration**: Retrieval leaks unauthorized documents or sensitive PII across tenant boundaries.
- **Hallucinated Misinformation**: Chatbots invent factual claims without grounding citations.
- **Output Injection & XSS**: Model responses output unescaped executable scripts.

ContextForge addresses these challenges by enforcing security decisions **in application code outside the LLM**, combining deterministic guardrails, RBAC access control, and grounding verification.

---

## Key Security Features

- **Zero-Cloud Local Execution**: Runs 100% locally with a deterministic mock provider and vector store. No AWS credentials or cloud services required.
- **Multi-Stage Injection Defense**: Combines regex pattern matching, instruction override detectors, role hijacking prevention, and prompt exfiltration filters.
- **Indirect Injection Isolation**: Strict boundary tagging (`<RETRIEVED_CONTEXT>`) treats retrieved passages strictly as passive reference data.
- **Policy-Driven PII Redaction**: Redacts emails, phone numbers, SSNs, credit cards (with Luhn checksum validation), and synthetic Canary secrets across input, retrieval, and output.
- **Retrieval Access Control (RBAC)**: Enforces document classification (`PUBLIC`, `INTERNAL`, `RESTRICTED`) in retrieval logic before passages reach the LLM.
- **SSRF-Protected Remote Ingestion**: Validates target IPs against private networks (RFC 1918), loopback, link-local, and AWS metadata endpoints (`169.254.169.254`).
- **Cryptographic Provenance**: Tracks publisher, source URL, page counts, and SHA-256 hashes to prevent document tampering and duplicate pollution.
- **Output Sanitization & Anti-XSS**: Escapes HTML entities and blocks responses if Canary secrets appear in output.
- **Grounding & Citation Enforcement**: Validates that all citations reference actual retrieved passages; explicitly abstains if evidence is insufficient.
- **Automated Adversarial Red-Team Suite**: CLI test harness evaluating 19 repeatable attack cases across all OWASP LLM categories.

---

## System Architecture

```
User Query ---> [Rate Limiter] ---> [Input Validator] ---> [Prompt Injection Detector] ---> [PII Redaction]
                                                                                                  |
                                                                                                  v
                               [Vector Store] <--- [RBAC Access Control] <--- [Retriever (Top-K / Min-Score)]
                                      |
                                      v
                             <RETRIEVED_CONTEXT> (Isolated Untrusted Container)
                                      |
                                      v
                             [LLM / Bedrock Provider]
                                      |
                                      v
                       [Output Filter: XSS Escaping & Canary Detection]
                                      |
                                      v
                       [Grounding Evaluator & Citation Verifier]
                                      |
                                      v
                     Sanitized Answer + Verified Citations + Disclaimer
```

---

## Technology Stack

- **Backend Runtime**: Python 3.11+ / Python 3.14
- **API Framework**: FastAPI, Uvicorn, Pydantic v2, Pydantic Settings
- **PDF Extraction**: PyPDF (safe parser with resource bounds and exploit scanning)
- **Vector Index**: In-memory dense cosine similarity with NumPy
- **Security Testing**: Pytest, Pytest-Cov, Bandit, Pip-Audit, Ruff
- **Cloud Provider (Optional)**: AWS Bedrock Converse API (`boto3`) & Bedrock Guardrails
- **Containerization**: Multi-stage hardened Docker image (non-root `contextforge` UID 10001)

---

## Project Structure

```
ContextForge/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI app with security middlewares
│   │   ├── config.py                   # Pydantic settings & environment configuration
│   │   ├── dependencies.py             # Dependency injection providers
│   │   ├── api/                        # REST routes (health, documents, chat, security)
│   │   ├── ingestion/                  # Safe PDF parser, document validator, chunker, provenance
│   │   ├── retrieval/                  # Local embeddings, vector store, retriever, source validation
│   │   ├── llm/                        # Base interface, deterministic mock provider, Bedrock provider, prompts
│   │   ├── security/                   # Input validation, prompt injection, PII redaction, output filter, grounding, ACL
│   │   ├── guardrails/                 # Pipeline orchestrator, policy models, Bedrock Guardrails wrapper
│   │   ├── evaluation/                 # Red-team runner CLI, scoring engine, test models
│   │   └── observability/              # Security event schemas and sanitized audit logging
│   └── tests/
│       ├── conftest.py                 # Pytest fixtures and test isolation
│       ├── unit/                       # Unit tests for all security controls
│       ├── integration/                # Full RAG & API endpoint integration tests
│       ├── security/                   # OWASP LLM Top 10 control verification tests
│       └── fixtures/                   # Test PDF fixtures (benign, exploit, poisoned)
├── documents/                          # Curated public aviation reference document manifests
├── redteam/                            # Repeatable adversarial test cases
├── evaluation/                         # Benchmark questions dataset
├── docs/                               # Comprehensive security, threat model, and architecture specs
├── .github/workflows/ci.yml            # Automated DevSecOps CI workflow
├── Dockerfile                          # Hardened container definition
├── pyproject.toml                      # Packaging & tooling configuration
├── .env.example                        # Configuration template
├── README.md                           # Master documentation
└── SECURITY.md                         # Responsible disclosure policy
```

---

## Prerequisites & Local Installation

### 1. Clone & Setup Virtual Environment

```bash
git clone https://github.com/ayus1n9/ContextForge.git
cd ContextForge

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install application and development dependencies
pip install --upgrade pip
pip install -e ".[dev]"
```

### 2. Configure Environment

Copy the example configuration:
```bash
cp .env.example .env
```
*(By default, `LLM_PROVIDER=mock`, which requires zero cloud credentials).*

### 3. Start Application Server

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Access the service at `http://127.0.0.1:8000`.

---

## API Usage Examples

### Health Check
```bash
curl -s http://127.0.0.1:8000/health
```

### Ingest a Document
```bash
curl -X POST http://127.0.0.1:8000/documents/upload \
  -F "file=@sample.pdf" \
  -F "doc_title=FAA Aerodynamics Manual" \
  -F "publisher=Federal Aviation Administration" \
  -F "classification=PUBLIC"
```

### Query Chat Under Full Guardrails
```bash
curl -X POST http://127.0.0.1:8000/chat/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the four forces acting on an aircraft in flight?"}'
```

---

## Adversarial Red-Team Suite & Evaluation

Execute the automated red-team test suite via CLI:

```bash
# Execute all adversarial categories
python3 -m backend.app.evaluation.redteam_runner --suite all --output redteam_results.json --report docs/red-team-results.md

# Execute prompt injection tests only
python3 -m backend.app.evaluation.redteam_runner --suite prompt-injection

# Execute PII disclosure tests only
python3 -m backend.app.evaluation.redteam_runner --suite pii
```

---

## Actual Evaluation Results

*Empirical metrics executed against 19 standardized adversarial and benign control cases:*

| Metric | Result | Target | Status |
| :--- | :--- | :--- | :--- |
| **Total Test Cases Executed** | **19** | 19 | Verified |
| **Tests Passed** | **19 / 19** | 100% | PASS |
| **Attack Blocking Rate** | **100.0%** | $\ge 95\%$ | PASS |
| **Benign False-Positive Rate** | **0.0%** | $0\%$ | PASS |
| **Direct Injection Block Rate** | **100.0%** (5/5 blocked) | 100% | PASS |
| **Indirect Injection Prevention** | **100.0%** (0 overrides executed) | 100% | PASS |
| **PII & Secret Disclosure Leakage** | **0.0%** (4/4 redacted) | 0% | PASS |
| **Citation Verification Accuracy** | **100.0%** (0 fabricated citations accepted) | 100% | PASS |

Full detailed breakdown is maintained in [docs/red-team-results.md](docs/red-team-results.md).

---

## Automated Tests & DevSecOps Verification

Run all unit, integration, and security tests with test coverage:

```bash
# Run pytest with code coverage
pytest --cov=backend/app --cov-report=term-missing backend/tests

# Static security analysis
bandit -r backend/app

# Dependency vulnerability audit
pip-audit

# Code style and linting
ruff check backend/app
```

---

## Docker Container Usage

Build and run the hardened container:

```bash
# Build Docker image
docker build -t contextforge:latest .

# Run container as unprivileged user
docker run -p 8000:8000 contextforge:latest
```

---

## Safety Considerations & Disclaimers

> [!CAUTION]
> **Aviation Safety Notice**: ContextForge is an educational document assistant. Generated answers must **NOT** be used as authoritative operational flight-safety, aircraft maintenance dispatch, or safety-critical engineering instructions. Always consult certified FAA/EASA flight manuals and licensed personnel.
