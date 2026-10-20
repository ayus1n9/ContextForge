"""Document Pre-Ingestion Security Validation.

Inspects raw PDF bytes prior to parsing:
- Magic bytes verification (%PDF-)
- File size bounds
- Malicious PDF active content tags (/Launch, /JavaScript, /SubmitForm)
- Stream corruption and truncation
"""

import hashlib
from typing import Optional, Tuple

from backend.app.config import settings
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)

MALICIOUS_PDF_TAGS = [
    (b"/JavaScript", "Embedded JavaScript detected"),
    (b"/JS", "Embedded JS action detected"),
    (b"/Launch", "Arbitrary launch/executable action detected"),
    (b"/SubmitForm", "Data exfiltration / form submission action detected"),
    (b"/ImportData", "Form data import action detected"),
    (b"/RichMedia", "Interactive rich media payload detected"),
]


class DocumentValidationError(ValueError):
    """Raised when a document fails security validation."""
    pass


class DocumentValidator:
    """Validates raw document bytes before passing to any parser."""

    def __init__(self, max_size_bytes: Optional[int] = None):
        self.max_size_bytes = max_size_bytes or settings.MAX_UPLOAD_SIZE_BYTES

    def validate_pdf_bytes(
        self,
        content: bytes,
        filename: str = "uploaded.pdf",
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], str]:
        """Validate raw PDF bytes for size, magic header, and active content exploits.

        Returns (is_valid, error_reason, sha256_hash).
        """
        sha256_hash = hashlib.sha256(content).hexdigest()

        # 1. Size bounds check
        if len(content) == 0:
            self._log_violation("Empty file upload rejected", "EMPTY_FILE", filename, correlation_id, client_ip)
            return False, "File is empty", sha256_hash

        if len(content) > self.max_size_bytes:
            self._log_violation(
                f"File size {len(content)} exceeds maximum {self.max_size_bytes}",
                "SIZE_LIMIT_EXCEEDED",
                filename,
                correlation_id,
                client_ip,
            )
            return False, f"File exceeds maximum size of {self.max_size_bytes} bytes", sha256_hash

        # 2. Magic bytes check
        if not content.startswith(b"%PDF-"):
            self._log_violation(
                "Invalid file header; missing %PDF- magic bytes",
                "INVALID_MAGIC_BYTES",
                filename,
                correlation_id,
                client_ip,
            )
            return False, "Invalid file format: missing %PDF- magic bytes", sha256_hash

        # 3. Active content exploit scanning
        for tag, reason in MALICIOUS_PDF_TAGS:
            if tag in content:
                self._log_violation(
                    f"Malicious PDF structure: {reason}",
                    "MALICIOUS_PDF_ACTION",
                    filename,
                    correlation_id,
                    client_ip,
                    severity=SecuritySeverity.HIGH,
                )
                return False, f"Security policy rejected PDF: {reason}", sha256_hash

        # 4. Basic structural integrity check
        if b"%%EOF" not in content[-2048:]:
            # Some PDFs have minor trailing whitespace, so search last 2048 bytes
            self._log_violation(
                "Malformed PDF: missing %%EOF termination marker",
                "MALFORMED_PDF_EOF",
                filename,
                correlation_id,
                client_ip,
                severity=SecuritySeverity.LOW,
            )
            return False, "Malformed PDF: missing %%EOF marker", sha256_hash

        return True, None, sha256_hash

    def _log_violation(
        self,
        description: str,
        reason: str,
        filename: str,
        correlation_id: Optional[str],
        client_ip: Optional[str],
        severity: SecuritySeverity = SecuritySeverity.MEDIUM,
    ) -> None:
        event = SecurityEvent(
            correlation_id=correlation_id or "unknown",
            category=SecurityEventCategory.DOCUMENT_SAFETY,
            decision=SecurityDecision.BLOCKED,
            severity=severity,
            description=description,
            client_ip=client_ip,
            details={"filename": filename, "reason": reason},
        )
        audit_logger.log_event(event)


# Default singleton instance
document_validator = DocumentValidator()
