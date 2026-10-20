# Security Policy

## Reporting a Vulnerability

The AegisRAG team takes security vulnerabilities seriously. We appreciate the responsible disclosure of security issues.

### Reporting Guidelines
If you discover a security vulnerability, prompt injection bypass, or sensitive data leakage in AegisRAG, please **do NOT report it through public GitHub issues**.

Instead, send a detailed report via encrypted email to:
- **Email**: `security@aegisrag.dev` (or open a confidential GitHub Security Advisory)

### Report Details
Please include:
1. Attack category (e.g. Direct Injection, Indirect Injection, PII Leakage, SSRF, XSS).
2. Step-by-step reproduction instructions or prompt payload.
3. Observed versus expected guardrail behavior.
4. Impact assessment.
5. Any proposed remediation.

### Response Timeline
- **Initial Response**: Within 48 hours acknowledging receipt.
- **Triage & Assessment**: Within 5 business days.
- **Fix & Disclosure**: Coordinated disclosure within 30 to 90 days depending on severity.

---

## Security Commitments

1. **Zero Secret Logging**: Application code is designed to never print API keys, AWS credentials, or raw PII into terminal logs, reports, or test artifacts.
2. **Deterministic Offline Testing**: Core automated test suites run without external network access or cloud credentials.
3. **No Unauthenticated Tools**: The application does not grant autonomous tool execution or shell execution capabilities to the model.
