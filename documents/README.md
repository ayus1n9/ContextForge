# AegisRAG Curated Public Reference Document Corpus

This repository uses public domain official technical reference publications from the **Federal Aviation Administration (FAA)** and the **National Aeronautics and Space Administration (NASA)**. 

Under 17 U.S.C. § 105, works prepared by an officer or employee of the United States Government as part of that person's official duties are not entitled to domestic copyright protection in the United States and reside in the public domain.

---

## Document Manifest and Provenance Registry

| Document ID | Title | Publisher | Publication Date | Source URL | SHA-256 Hash | Pages | Ingestion Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `faa-phak-ch05` | FAA Pilot's Handbook of Aeronautical Knowledge: Chapter 5 - Aerodynamics of Flight | Federal Aviation Administration (FAA) | 2023 | [FAA Official Handbooks](https://www.faa.gov/regulations_policies/handbooks_manuals/aviation/phak) | `9c84e1b9f71c4c92a6df7a0d4cbb8f921d7b1a23806bf3a71b307409c9102c44` | 2 | Verified Ingested |
| `faa-phak-ch10` | FAA Pilot's Handbook of Aeronautical Knowledge: Chapter 10 - Weight and Balance | Federal Aviation Administration (FAA) | 2023 | [FAA Official Handbooks](https://www.faa.gov/regulations_policies/handbooks_manuals/aviation/phak) | `e2a7b88c3f592d04a6e872c9bc44d715a3bb405e32158f902dc6787865241b80` | 2 | Verified Ingested |
| `nasa-sp-546` | NASA Systems Engineering Handbook Excerpts | National Aeronautics and Space Administration (NASA) | 2020 | [NASA Technical Reports](https://ntrs.nasa.gov/) | `7a118df042b31a89c441865a9ef4e2cfc21685a4980a370e0a5c4d32bb58269d` | 2 | Verified Ingested |

---

## Ingestion Safety Rules

1. Every document undergoes pre-ingestion security scanning to verify standard `%PDF-` magic bytes and absence of active executable tags (`/Launch`, `/JavaScript`, `/SubmitForm`).
2. Documents exceeding `MAX_PDF_PAGES` (50 pages) or `MAX_UPLOAD_SIZE_BYTES` (10 MB) are automatically rejected.
3. Stable cryptographic hashes (SHA-256) prevent redundant re-ingestion and vector space pollution.
4. Remote URL ingestion applies strict IP address validation to prevent Server-Side Request Forgery (SSRF) targeting loopback, private RFC-1918 subnets, or AWS cloud metadata endpoints (`169.254.169.254`).
