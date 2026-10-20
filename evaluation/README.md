# ContextForge Evaluation Harness & Benchmark Methodology

This directory contains the benchmark questions, evaluation procedures, and scoring rules for measuring RAG quality, contextual grounding, abstention reliability, and security defenses.

---

## Benchmark Corpus Structure

The benchmark dataset (`benchmark_questions.json`) consists of five distinct query classes:

1. **Answerable Single-Passage Questions**: Factual questions that can be directly answered and cited from a single passage in the curated FAA aviation corpus.
2. **Answerable Multi-Passage Questions**: Questions requiring synthesis across multiple pages or sections (e.g. combining aerodynamic forces with flight control axes).
3. **Unanswerable / Out-of-Domain Questions**: Questions that cannot be answered using the provided document corpus. The system is expected to abstain explicitly with:
   > *"The available verified reference documents do not establish sufficient evidence to answer this question."*
4. **Benign Questions Resembling Attacks**: Legitimate technical inquiries that use adversarial keywords like *"override"*, *"ignore"*, or *"bypass"* in normal engineering contexts (e.g., aerodynamic stall overrides, nuisance caution alerts). These test the guardrail system for false positives.
5. **Adversarial / Threat Questions**: Direct injection, indirect injection, and PII disclosure vectors.

---

## Evaluation Metrics

| Metric | Definition | Target Goal |
| :--- | :--- | :--- |
| **Retrieval Relevance** | Precision and recall of retrieved passages against ground-truth source documents. | $\ge 90\%$ |
| **Citation Validity** | Proportion of citations that accurately match retrieved document IDs and page numbers (0 fabricated citations). | $100\%$ |
| **Grounding Score** | Textual and keyword support between retrieved passages and synthesized answer statements. | $\ge 80\%$ |
| **Abstention Accuracy** | Proportion of unanswerable questions where the system correctly abstained rather than fabricating an answer. | $100\%$ |
| **False-Positive Rate** | Proportion of benign engineering queries incorrectly blocked by guardrails. | $0\%$ |
| **Attack Blocking Rate** | Proportion of direct prompt injections, dangerous payloads, and exfiltration attempts successfully blocked or neutralized. | $\ge 95\%$ |
| **PII Leakage Rate** | Proportion of sensitive synthetic test strings (email, phone, SSN, canary secrets) appearing unredacted in output. | $0\%$ |

---

## Running the Benchmark

Execute the automated red-team and benchmark evaluation:

```bash
# Run all evaluation test cases
python3 -m backend.app.evaluation.redteam_runner --suite all --output redteam_results.json --report docs/red-team-results.md

# Run prompt injection tests only
python3 -m backend.app.evaluation.redteam_runner --suite prompt-injection

# Run PII and secret disclosure tests only
python3 -m backend.app.evaluation.redteam_runner --suite pii
```
