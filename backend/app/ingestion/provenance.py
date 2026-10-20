"""Document Provenance and Metadata Registry.

Tracks origin, cryptographic integrity, page counts, publisher,
and access classification for every ingested document.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from backend.app.security.access_control import DocumentClassification


class DocumentProvenance(BaseModel):
    doc_id: str
    doc_title: str
    publisher: str
    source_url: Optional[str] = None
    publication_date: Optional[str] = None
    retrieval_date: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    sha256_hash: str
    file_size_bytes: int
    page_count: int
    classification: DocumentClassification = DocumentClassification.PUBLIC
    allowed_roles: List[str] = Field(default_factory=lambda: ["viewer", "engineer", "admin"])
    ingestion_status: str = "SUCCESS"  # SUCCESS, FAILED, PENDING
    extraction_status: str = "COMPLETED"  # COMPLETED, FAILED
    error_message: Optional[str] = None


class ProvenanceRegistry:
    """In-memory and persistent registry of document provenance records."""

    def __init__(self):
        self._documents: Dict[str, DocumentProvenance] = {}
        self._hash_to_id: Dict[str, str] = {}

    def register(self, doc: DocumentProvenance) -> None:
        """Register or update document provenance."""
        self._documents[doc.doc_id] = doc
        self._hash_to_id[doc.sha256_hash] = doc.doc_id

    def get_by_id(self, doc_id: str) -> Optional[DocumentProvenance]:
        return self._documents.get(doc_id)

    def get_by_hash(self, sha256_hash: str) -> Optional[DocumentProvenance]:
        doc_id = self._hash_to_id.get(sha256_hash)
        return self._documents.get(doc_id) if doc_id else None

    def list_all(self) -> List[DocumentProvenance]:
        return list(self._documents.values())

    def clear(self) -> None:
        self._documents.clear()
        self._hash_to_id.clear()


# Default singleton instance
provenance_registry = ProvenanceRegistry()
