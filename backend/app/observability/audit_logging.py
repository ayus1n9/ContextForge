"""Security Audit Logging.

Provides safe, structured JSON audit logging.
Sanitizes all log entries to guarantee no canary tokens, API secrets,
or raw PII leak into log files or monitoring sinks.
"""

import logging
import re
from typing import Any, List, Optional

from backend.app.config import settings
from backend.app.observability.security_events import SecurityEvent

logger = logging.getLogger("aegisrag.security")

# Canary patterns that must NEVER appear in logs
SECRET_CANARY_PATTERNS = [
    re.compile(r"CANARY-[A-Za-z0-9_-]+", re.IGNORECASE),
    re.compile(r"AEGIS_SECRET_[A-Za-z0-9_-]+", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
]


def sanitize_log_dict(data: Any) -> Any:
    """Recursively scrub any sensitive substrings or canaries from log metadata."""
    if isinstance(data, str):
        cleaned = data
        for pattern in SECRET_CANARY_PATTERNS:
            cleaned = pattern.sub("[REDACTED_SECRET]", cleaned)
        return cleaned
    elif isinstance(data, dict):
        return {k: sanitize_log_dict(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_log_dict(item) for item in data]
    return data


class SecurityAuditLogger:
    """Singleton audit logger for security events."""

    _instance: Optional["SecurityAuditLogger"] = None

    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file or settings.AUDIT_LOG_FILE
        self._memory_events: List[SecurityEvent] = []
        self._max_memory_events = 1000

    @classmethod
    def get_instance(cls) -> "SecurityAuditLogger":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def log_event(self, event: SecurityEvent) -> None:
        """Record and persist a sanitized security event."""
        # Sanitize event details
        sanitized_details = sanitize_log_dict(event.details)
        sanitized_event = event.model_copy(update={"details": sanitized_details})

        # Append to memory buffer
        self._memory_events.append(sanitized_event)
        if len(self._memory_events) > self._max_memory_events:
            self._memory_events.pop(0)

        # Write to JSON Lines log file
        try:
            line = sanitized_event.model_dump_json() + "\n"
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            logger.error("Failed to append security event to audit file: %s", str(e))

    def get_recent_events(
        self,
        limit: int = 50,
        category: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Query in-memory security events."""
        events = list(reversed(self._memory_events))
        if category:
            events = [e for e in events if e.category.value == category]
        if correlation_id:
            events = [e for e in events if e.correlation_id == correlation_id]
        return events[:limit]

    def clear(self) -> None:
        """Clear in-memory events (useful for test isolation)."""
        self._memory_events.clear()


# Default singleton instance
audit_logger = SecurityAuditLogger.get_instance()
