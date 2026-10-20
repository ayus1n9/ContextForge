"""Input Validation Security Layer.

Validates all incoming user messages and API requests.
Protects against buffer-overflow-like payloads, null-byte injection,
control-character manipulation, and excessive input sizing.
"""

from typing import Optional, Tuple

from backend.app.config import settings
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)


class InputValidationError(ValueError):
    """Exception raised when input validation fails."""
    pass


class InputValidator:
    """Validates user text inputs for length, character integrity, and malformed encoding."""

    def __init__(self, max_length: Optional[int] = None):
        self.max_length = max_length or settings.MAX_INPUT_LENGTH_CHARS

    def validate_query(
        self,
        query: str,
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Validate an incoming user query.

        Returns (is_valid, error_message).
        """
        if not isinstance(query, str):
            self._log_failure(
                "Input must be a string",
                correlation_id,
                client_ip,
                reason="INVALID_TYPE",
            )
            return False, "Input must be a string"

        stripped = query.strip()
        if not stripped:
            self._log_failure(
                "Input query cannot be empty or purely whitespace",
                correlation_id,
                client_ip,
                reason="EMPTY_INPUT",
            )
            return False, "Query cannot be empty"

        if len(query) > self.max_length:
            self._log_failure(
                f"Input length {len(query)} exceeds maximum allowed {self.max_length}",
                correlation_id,
                client_ip,
                reason="LENGTH_EXCEEDED",
                details={"length": len(query), "max_allowed": self.max_length},
            )
            return False, f"Query exceeds maximum length of {self.max_length} characters"

        # Check for null bytes
        if "\x00" in query:
            self._log_failure(
                "Input contains illegal null bytes",
                correlation_id,
                client_ip,
                reason="NULL_BYTE_DETECTED",
            )
            return False, "Query contains illegal null byte characters"

        # Check for non-printable control characters (excluding standard whitespace \t, \n, \r)
        control_chars = [
            char for char in query
            if ord(char) < 32 and char not in ("\t", "\n", "\r")
        ]
        if control_chars:
            self._log_failure(
                "Input contains prohibited control characters",
                correlation_id,
                client_ip,
                reason="CONTROL_CHARACTERS_DETECTED",
                details={"control_char_count": len(control_chars)},
            )
            return False, "Query contains invalid control characters"

        return True, None

    def _log_failure(
        self,
        description: str,
        correlation_id: Optional[str],
        client_ip: Optional[str],
        reason: str,
        details: Optional[dict] = None,
    ) -> None:
        event = SecurityEvent(
            correlation_id=correlation_id or "unknown",
            category=SecurityEventCategory.INPUT_VALIDATION,
            decision=SecurityDecision.BLOCKED,
            severity=SecuritySeverity.MEDIUM,
            description=description,
            client_ip=client_ip,
            details={"reason": reason, **(details or {})},
        )
        audit_logger.log_event(event)


# Default singleton instance
input_validator = InputValidator()
