"""Document Ingestion Orchestration Pipeline.

Coordinates:
- Security validation
- PDF text extraction
- Provenance recording & SHA-256 deduplication
- Chunking & vector index loading
- SSRF-safe remote document retrieval
"""

import ipaddress
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from backend.app.config import settings
from backend.app.ingestion.chunking import text_chunker
from backend.app.ingestion.document_validation import document_validator
from backend.app.ingestion.pdf_parser import safe_pdf_parser
from backend.app.ingestion.provenance import DocumentProvenance, provenance_registry
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)
from backend.app.security.access_control import DocumentClassification


class SSRFSecurityError(ValueError):
    """Raised when a remote URL targets prohibited or internal network destinations."""
    pass


class IngestionPipeline:
    """Manages secure document intake from local files and remote official sources."""

    def ingest_pdf_bytes(
        self,
        content: bytes,
        filename: str,
        doc_title: str,
        publisher: str,
        source_url: Optional[str] = None,
        publication_date: Optional[str] = None,
        classification: DocumentClassification = DocumentClassification.PUBLIC,
        allowed_roles: Optional[List[str]] = None,
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingest a raw PDF byte stream with full security checks and deduplication."""
        # 1. Pre-ingestion validation
        is_valid, error_reason, sha256_hash = document_validator.validate_pdf_bytes(
            content=content,
            filename=filename,
            correlation_id=correlation_id,
            client_ip=client_ip,
        )
        if not is_valid:
            return {
                "status": "FAILED",
                "error": error_reason,
                "sha256_hash": sha256_hash,
                "chunks_count": 0,
            }

        # 2. Check for duplicate document
        existing = provenance_registry.get_by_hash(sha256_hash)
        if existing:
            return {
                "status": "DUPLICATE",
                "message": f"Document already ingested with ID '{existing.doc_id}'",
                "doc_id": existing.doc_id,
                "sha256_hash": sha256_hash,
                "chunks_count": 0,
            }

        # 3. Extract pages
        try:
            pages = safe_pdf_parser.extract_pages(
                content=content,
                filename=filename,
                correlation_id=correlation_id,
                client_ip=client_ip,
            )
        except Exception as e:
            return {
                "status": "FAILED",
                "error": str(e),
                "sha256_hash": sha256_hash,
                "chunks_count": 0,
            }

        # 4. Generate doc_id and chunk text
        doc_id = filename.lower().replace(".pdf", "").replace(" ", "-")
        chunks = text_chunker.chunk_pages(
            pages=pages,
            doc_id=doc_id,
            doc_title=doc_title,
            source_url=source_url,
            classification=classification.value,
            allowed_roles=allowed_roles,
        )

        # 5. Record provenance
        provenance = DocumentProvenance(
            doc_id=doc_id,
            doc_title=doc_title,
            publisher=publisher,
            source_url=source_url,
            publication_date=publication_date,
            sha256_hash=sha256_hash,
            file_size_bytes=len(content),
            page_count=len(pages),
            classification=classification,
            allowed_roles=allowed_roles or ["viewer", "engineer", "admin"],
            ingestion_status="SUCCESS",
            extraction_status="COMPLETED",
        )
        provenance_registry.register(provenance)

        # 6. Log success event
        event = SecurityEvent(
            correlation_id=correlation_id or "unknown",
            category=SecurityEventCategory.DOCUMENT_SAFETY,
            decision=SecurityDecision.ALLOWED,
            severity=SecuritySeverity.LOW,
            description=f"Successfully ingested '{doc_title}' ({len(chunks)} chunks)",
            client_ip=client_ip,
            details={
                "doc_id": doc_id,
                "sha256_hash": sha256_hash,
                "page_count": len(pages),
                "chunk_count": len(chunks),
                "classification": classification.value,
            },
        )
        audit_logger.log_event(event)

        return {
            "status": "SUCCESS",
            "doc_id": doc_id,
            "doc_title": doc_title,
            "sha256_hash": sha256_hash,
            "page_count": len(pages),
            "chunks_count": len(chunks),
            "chunks": chunks,
        }

    def fetch_remote_pdf(
        self,
        url: str,
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> bytes:
        """Safely fetch a PDF from an external URL with comprehensive SSRF protection."""
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            self._log_ssrf_attempt("Prohibited scheme; only HTTPS is permitted", url, correlation_id, client_ip)
            raise SSRFSecurityError("Only secure HTTPS URLs are permitted")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFSecurityError("Invalid URL hostname")

        # Resolve IP and check for private / internal addresses
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
        except Exception as e:
            raise SSRFSecurityError(f"DNS resolution failure for {hostname}: {str(e)}") from e

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or str(ip_obj) == "169.254.169.254"  # AWS Cloud Metadata IP
        ):
            self._log_ssrf_attempt(
                f"Prohibited destination IP {ip_str} (Internal/Loopback/Metadata endpoint)",
                url,
                correlation_id,
                client_ip,
            )
            raise SSRFSecurityError(f"Prohibited network target: destination IP {ip_str} is disallowed")

        # Perform controlled fetch with size limit and timeout
        client = httpx.Client(timeout=15.0, follow_redirects=False)
        try:
            resp = client.get(url)
            resp.raise_for_status()
            content = resp.content

            if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
                raise SSRFSecurityError(
                    f"Remote file exceeds maximum limit of {settings.MAX_UPLOAD_SIZE_BYTES} bytes"
                )
            return content
        except httpx.HTTPStatusError as e:
            raise SSRFSecurityError(f"HTTP error downloading document: {e.response.status_code}") from e
        except Exception as e:
            raise SSRFSecurityError(f"Download failed: {str(e)}") from e
        finally:
            client.close()

    def _log_ssrf_attempt(
        self,
        reason: str,
        target_url: str,
        correlation_id: Optional[str],
        client_ip: Optional[str],
    ) -> None:
        event = SecurityEvent(
            correlation_id=correlation_id or "unknown",
            category=SecurityEventCategory.DOCUMENT_SAFETY,
            decision=SecurityDecision.BLOCKED,
            severity=SecuritySeverity.CRITICAL,
            description=f"SSRF violation blocked: {reason}",
            client_ip=client_ip,
            details={"target_url": target_url, "reason": reason},
        )
        audit_logger.log_event(event)


# Default singleton instance
ingestion_pipeline = IngestionPipeline()
