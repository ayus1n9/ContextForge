"""Safe PDF Text Extraction Parser.

Extracts text page-by-page using pypdf under strict resource limits:
- Page count cap (default max 50 pages)
- Handles encrypted / password-protected files safely
- Sanitizes extracted text characters
- Preserves 1-indexed page numbers
"""

import io
from typing import List, Optional, Tuple

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from backend.app.config import settings
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)


class PDFParsingError(Exception):
    """Exception raised when PDF parsing fails."""
    pass


class SafePDFParser:
    """Safe text extractor for PDF documents."""

    def __init__(self, max_pages: Optional[int] = None):
        self.max_pages = max_pages or settings.MAX_PDF_PAGES

    def extract_pages(
        self,
        content: bytes,
        filename: str = "document.pdf",
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> List[Tuple[int, str]]:
        """Extract text page-by-page from raw PDF bytes.

        Returns list of (page_number, extracted_text).
        """
        try:
            reader = PdfReader(io.BytesIO(content))
        except PdfReadError as e:
            self._log_error(
                f"PDF read error in {filename}: {str(e)}",
                "PDF_READ_ERROR",
                filename,
                correlation_id,
                client_ip,
            )
            raise PDFParsingError(f"Failed to read PDF structure: {str(e)}") from e
        except Exception as e:
            self._log_error(
                f"Unexpected PDF reader error in {filename}: {str(e)}",
                "PARSER_EXCEPTION",
                filename,
                correlation_id,
                client_ip,
            )
            raise PDFParsingError(f"Unexpected error while opening PDF: {str(e)}") from e

        # Check encryption
        if reader.is_encrypted:
            self._log_error(
                f"Encrypted PDF rejected: {filename}",
                "ENCRYPTED_PDF",
                filename,
                correlation_id,
                client_ip,
            )
            raise PDFParsingError("Password-protected or encrypted PDFs are not supported")

        page_count = len(reader.pages)
        if page_count > self.max_pages:
            self._log_error(
                f"PDF page count {page_count} exceeds maximum allowed {self.max_pages}",
                "PAGE_LIMIT_EXCEEDED",
                filename,
                correlation_id,
                client_ip,
            )
            raise PDFParsingError(
                f"PDF exceeds maximum page limit ({page_count} > {self.max_pages})"
            )

        extracted_pages: List[Tuple[int, str]] = []
        for idx, page in enumerate(reader.pages):
            page_num = idx + 1
            try:
                page_text = page.extract_text() or ""
            except Exception:
                # Log page extraction issue but continue with remaining pages
                page_text = ""

            # Sanitize text: remove null bytes and control chars
            sanitized_text = "".join(
                c for c in page_text if c == "\n" or c == "\t" or ord(c) >= 32
            ).strip()

            if sanitized_text:
                extracted_pages.append((page_num, sanitized_text))

        if not extracted_pages:
            raise PDFParsingError("No extractable text found in PDF (document may be scanned or empty)")

        return extracted_pages

    def _log_error(
        self,
        description: str,
        reason: str,
        filename: str,
        correlation_id: Optional[str],
        client_ip: Optional[str],
    ) -> None:
        event = SecurityEvent(
            correlation_id=correlation_id or "unknown",
            category=SecurityEventCategory.DOCUMENT_SAFETY,
            decision=SecurityDecision.BLOCKED,
            severity=SecuritySeverity.MEDIUM,
            description=description,
            client_ip=client_ip,
            details={"filename": filename, "reason": reason},
        )
        audit_logger.log_event(event)


# Default singleton instance
safe_pdf_parser = SafePDFParser()
