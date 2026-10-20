"""Source Validation Layer.

Verifies that retrieved chunks and document IDs exist in the active
provenance registry and have not been tampered with or fabricated.
"""

from typing import Any, Dict, List, Tuple

from backend.app.ingestion.provenance import provenance_registry


class SourceValidator:
    """Validates retrieved chunks against known document provenance records."""

    def validate_retrieved_sources(
        self,
        chunks: List[Dict[str, Any]],
    ) -> Tuple[bool, List[str]]:
        """Verify that all chunks originate from valid, registered documents."""
        invalid_sources = []

        for chunk in chunks:
            meta = chunk.get("metadata", {})
            doc_id = meta.get("doc_id")
            if not doc_id:
                invalid_sources.append("Chunk missing doc_id")
                continue

            doc_record = provenance_registry.get_by_id(doc_id)
            if not doc_record:
                invalid_sources.append(f"Unregistered document ID: {doc_id}")
            elif doc_record.ingestion_status != "SUCCESS":
                invalid_sources.append(f"Document {doc_id} has invalid status {doc_record.ingestion_status}")

        is_valid = len(invalid_sources) == 0
        return is_valid, invalid_sources


# Default singleton instance
source_validator = SourceValidator()
