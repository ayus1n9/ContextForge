"""Shared Pytest Configuration and Test Fixtures for AegisRAG."""

import os
import pytest
from fastapi.testclient import TestClient
from backend.app.config import settings
from backend.app.ingestion.provenance import provenance_registry
from backend.app.main import app
from backend.app.observability.audit_logging import audit_logger
from backend.app.retrieval.vector_store import vector_store
from backend.app.security.rate_limits import rate_limiter
from backend.tests.fixtures.pdf_builder import (
    create_faa_aerodynamics_pdf,
    create_indirect_injection_pdf,
    create_malicious_exploit_pdf,
)


@pytest.fixture(autouse=True)
def clean_test_state():
    """Reset rate limiter and audit state between tests."""
    rate_limiter.reset()
    yield
    rate_limiter.reset()


@pytest.fixture
def client():
    """FastAPI TestClient instance."""
    return TestClient(app)


@pytest.fixture
def sample_faa_pdf():
    """Returns valid binary PDF bytes for FAA aerodynamics excerpt."""
    return create_faa_aerodynamics_pdf()


@pytest.fixture
def sample_malicious_pdf():
    """Returns malicious PDF bytes with /Launch exploit tag."""
    return create_malicious_exploit_pdf("/Launch")


@pytest.fixture
def sample_indirect_pdf():
    """Returns adversarial PDF bytes with embedded override instructions."""
    return create_indirect_injection_pdf()
