"""Unit Tests for Document Validation, PDF Parser, and Chunking."""

import pytest
from backend.app.ingestion.chunking import text_chunker
from backend.app.ingestion.document_validation import document_validator
from backend.app.ingestion.pdf_parser import PDFParsingError, safe_pdf_parser
from backend.app.ingestion.provenance import DocumentProvenance, provenance_registry
from backend.tests.fixtures.pdf_builder import (
    create_faa_aerodynamics_pdf,
    create_malicious_exploit_pdf,
)


def test_validate_valid_pdf():
    pdf_bytes = create_faa_aerodynamics_pdf()
    valid, err, sha = document_validator.validate_pdf_bytes(pdf_bytes, "faa.pdf")
    assert valid is True
    assert err is None
    assert len(sha) == 64


def test_reject_non_pdf_magic_bytes():
    fake_bytes = b"NOT_A_PDF_FILE_HEADER"
    valid, err, _ = document_validator.validate_pdf_bytes(fake_bytes, "fake.pdf")
    assert valid is False
    assert "magic bytes" in err.lower()


def test_reject_malicious_launch_action():
    exploit_bytes = create_malicious_exploit_pdf("/Launch")
    valid, err, _ = document_validator.validate_pdf_bytes(exploit_bytes, "exploit.pdf")
    assert valid is False
    assert "launch" in err.lower()


def test_reject_malicious_javascript_action():
    exploit_bytes = create_malicious_exploit_pdf("/JavaScript")
    valid, err, _ = document_validator.validate_pdf_bytes(exploit_bytes, "exploit.pdf")
    assert valid is False
    assert "javascript" in err.lower()


def test_safe_pdf_extraction():
    pdf_bytes = create_faa_aerodynamics_pdf()
    pages = safe_pdf_parser.extract_pages(pdf_bytes, "faa.pdf")
    assert len(pages) == 2
    # Verify page 1 contains aerodynamic forces
    assert "Aerodynamics of Flight" in pages[0][1]
    assert pages[0][0] == 1
    # Verify page 2 contains primary flight controls
    assert "Primary Flight Control Systems" in pages[1][1]
    assert pages[1][0] == 2


def test_page_limit_enforced():
    parser_small = safe_pdf_parser.__class__(max_pages=1)
    pdf_bytes = create_faa_aerodynamics_pdf()  # has 2 pages
    with pytest.raises(PDFParsingError) as exc_info:
        parser_small.extract_pages(pdf_bytes, "too_long.pdf")
    assert "exceeds maximum page limit" in str(exc_info.value)


def test_chunking_preserves_provenance():
    pages = [
        (1, "The four forces of flight are lift, weight, thrust, and drag in aviation."),
        (2, "Ailerons control roll about the longitudinal axis."),
    ]
    chunks = text_chunker.chunk_pages(
        pages=pages,
        doc_id="doc-test-1",
        doc_title="Test Flight Manual",
        classification="PUBLIC",
    )
    assert len(chunks) == 2
    assert chunks[0].page_number == 1
    assert chunks[0].doc_id == "doc-test-1"
    assert chunks[1].page_number == 2
    assert chunks[1].doc_title == "Test Flight Manual"
    assert len(chunks[0].chunk_hash) == 64
