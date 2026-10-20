"""Text Chunking and Metadata Preservation.

Splits document text into overlapping windows while attaching
strict provenance, page numbers, and stable SHA-256 chunk hashes.
Prevents duplicate chunks from polluting the vector index.
"""

import hashlib
from typing import Any, Dict, List, Tuple

from pydantic import BaseModel, Field

from backend.app.config import settings


class TextChunk(BaseModel):
    chunk_id: str
    chunk_hash: str
    doc_id: str
    doc_title: str
    page_number: int
    text: str
    chunk_index: int
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TextChunker:
    """Sliding-window text chunker preserving page boundaries and cryptographic hashes."""

    def __init__(
        self,
        chunk_size: int = settings.CHUNK_SIZE,
        chunk_overlap: int = settings.CHUNK_OVERLAP,
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk_pages(
        self,
        pages: List[Tuple[int, str]],
        doc_id: str,
        doc_title: str,
        source_url: str = None,
        classification: str = "PUBLIC",
        allowed_roles: List[str] = None,
    ) -> List[TextChunk]:
        """Convert page texts into a list of TextChunk objects."""
        chunks: List[TextChunk] = []
        global_chunk_idx = 0
        seen_hashes = set()

        for page_num, page_text in pages:
            text = page_text.strip()
            if not text:
                continue

            start = 0
            while start < len(text):
                end = min(start + self.chunk_size, len(text))
                chunk_str = text[start:end].strip()

                if len(chunk_str) >= 20:  # Skip trivial micro-fragments
                    chunk_hash = hashlib.sha256(
                        f"{doc_id}:{page_num}:{chunk_str}".encode("utf-8")
                    ).hexdigest()

                    # Deduplicate identical chunks
                    if chunk_hash not in seen_hashes:
                        seen_hashes.add(chunk_hash)
                        chunk_id = f"{doc_id}-p{page_num}-c{global_chunk_idx}"

                        meta = {
                            "doc_id": doc_id,
                            "doc_title": doc_title,
                            "page_number": page_num,
                            "source_url": source_url,
                            "classification": classification,
                            "allowed_roles": allowed_roles or ["viewer", "engineer", "admin"],
                            "chunk_index": global_chunk_idx,
                            "chunk_hash": chunk_hash,
                        }

                        chunks.append(
                            TextChunk(
                                chunk_id=chunk_id,
                                chunk_hash=chunk_hash,
                                doc_id=doc_id,
                                doc_title=doc_title,
                                page_number=page_num,
                                text=chunk_str,
                                chunk_index=global_chunk_idx,
                                metadata=meta,
                            )
                        )
                        global_chunk_idx += 1

                if end == len(text):
                    break
                start += max(1, self.chunk_size - self.chunk_overlap)

        return chunks


# Default singleton instance
text_chunker = TextChunker()
