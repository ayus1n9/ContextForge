# Technical Limitations and Residual Risks

ContextForge is built with defense-in-depth security principles. However, in accordance with responsible AI security engineering, the following limitations and residual risks are explicitly documented:

---

## 1. Prompt Injection Cannot Be 100% Eliminated
- Direct and indirect prompt injection are fundamental open challenges in language model architectures.
- ContextForge combines deterministic regex rules, heuristic scoring, isolated prompt boundaries, and output filtering.
- While this layered approach blocks all test cases in the defined adversarial suite, sophisticated multi-turn linguistic manipulation, novel ciphers, or multi-lingual obfuscation may occasionally evade pattern detection.

---

## 2. PII Detection Limitations
- PII detection uses regex patterns and algorithmic checksum validation (Luhn algorithm for payment cards).
- Pattern-based detection excels at structured identifiers (email addresses, phone numbers, SSNs, credit cards, Canary secrets).
- Unstructured personal data (such as names of private individuals mentioned in narrative text or non-standard government ID formats) cannot be reliably detected by regex alone without specialized named-entity recognition (NER) models.

---

## 3. High-Stakes Aviation and Operational Safety
- AegisRAG is an **educational and technical reference document assistant**.
- Generated responses must **never** be treated as authoritative operational flight-safety, aircraft maintenance dispatch, or airworthiness certification instructions.
- Real-world flight operations require consulting certified, up-to-date FAA/EASA manuals and qualified licensed aviation personnel.

---

## 4. Vector Retrieval and Grounding
- In-memory cosine similarity and n-gram hash embeddings provide fast, deterministic offline performance for development and test execution.
- Hash-based embeddings do not capture deep semantic analogies to the same depth as large dense transformer embedding models.
- For high-volume production deployments, connecting a dense embedding provider (e.g. Amazon Titan or HuggingFace BGE) and persistent vector database (e.g., OpenSearch or pgvector) is recommended.
