"""Retrieval Authorization and Access Control Layer.

Enforces document-level and tenant/role-level authorization in backend logic
BEFORE retrieved passages are sent to the model context.
Prevents cross-user leakage, metadata filter bypasses, and unauthorized document exfiltration.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import (
    SecurityDecision,
    SecurityEvent,
    SecurityEventCategory,
    SecuritySeverity,
)


class DocumentClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


class UserContext(BaseModel):
    user_id: str = "anonymous"
    roles: List[str] = Field(default_factory=lambda: ["viewer"])
    clearance: DocumentClassification = DocumentClassification.PUBLIC


class AccessControlEnforcer:
    """Evaluates document classification and user clearance to enforce authorization."""

    # Clearance hierarchy: RESTRICTED > INTERNAL > PUBLIC
    CLEARANCE_HIERARCHY: Dict[DocumentClassification, int] = {
        DocumentClassification.PUBLIC: 1,
        DocumentClassification.INTERNAL: 2,
        DocumentClassification.RESTRICTED: 3,
    }

    def can_access_document(
        self,
        user: UserContext,
        doc_metadata: Dict[str, Any],
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> bool:
        """Check if user has sufficient clearance and role to access a document."""
        doc_class_str = doc_metadata.get("classification", DocumentClassification.PUBLIC.value)
        try:
            doc_class = DocumentClassification(doc_class_str)
        except ValueError:
            doc_class = DocumentClassification.RESTRICTED

        user_level = self.CLEARANCE_HIERARCHY.get(user.clearance, 1)
        doc_level = self.CLEARANCE_HIERARCHY.get(doc_class, 3)

        # Clearance check
        if user_level < doc_level:
            self._log_denial(
                user=user,
                doc_metadata=doc_metadata,
                reason=f"Insufficient clearance (User: {user.clearance.value}, Doc: {doc_class.value})",
                correlation_id=correlation_id,
                client_ip=client_ip,
            )
            return False

        # Role restriction check
        allowed_roles = doc_metadata.get("allowed_roles")
        if allowed_roles:
            user_roles_set = set(user.roles)
            if not user_roles_set.intersection(set(allowed_roles)):
                self._log_denial(
                    user=user,
                    doc_metadata=doc_metadata,
                    reason=f"Role mismatch (User roles: {user.roles}, Allowed: {allowed_roles})",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                )
                return False

        return True

    def filter_chunks(
        self,
        chunks: List[Dict[str, Any]],
        user: UserContext,
        correlation_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Filter a list of retrieved chunks to only those the user is authorized to read."""
        authorized_chunks = []
        for chunk in chunks:
            metadata = chunk.get("metadata", {})
            if self.can_access_document(user, metadata, correlation_id, client_ip):
                authorized_chunks.append(chunk)
        return authorized_chunks

    def _log_denial(
        self,
        user: UserContext,
        doc_metadata: Dict[str, Any],
        reason: str,
        correlation_id: Optional[str],
        client_ip: Optional[str],
    ) -> None:
        event = SecurityEvent(
            correlation_id=correlation_id or "unknown",
            category=SecurityEventCategory.RETRIEVAL_AUTHORIZATION,
            decision=SecurityDecision.BLOCKED,
            severity=SecuritySeverity.HIGH,
            description=f"Retrieval access denied for document '{doc_metadata.get('doc_id')}': {reason}",
            client_ip=client_ip,
            details={
                "user_id": user.user_id,
                "user_clearance": user.clearance.value,
                "doc_id": doc_metadata.get("doc_id"),
                "doc_classification": doc_metadata.get("classification"),
                "reason": reason,
            },
        )
        audit_logger.log_event(event)


# Default singleton instance
access_control = AccessControlEnforcer()
