"""Unit Tests for Output Security and Sanitization Layer."""

import pytest
from backend.app.observability.security_events import SecurityDecision
from backend.app.security.output_filter import AVIATION_SAFETY_DISCLAIMER, OutputFilter


@pytest.fixture
def filter_engine():
    return OutputFilter()


def test_clean_output(filter_engine):
    clean_text = "The elevator controls pitch about the lateral axis."
    res = filter_engine.validate_and_sanitize(clean_text, attach_disclaimer=False)
    assert res.is_safe is True
    assert res.decision == SecurityDecision.ALLOWED
    assert "The elevator controls" in res.sanitized_text


def test_xss_script_neutralized(filter_engine):
    xss_payload = "Here is the result: <script>alert('XSS')</script>"
    res = filter_engine.validate_and_sanitize(xss_payload, attach_disclaimer=False)
    assert res.is_safe is True
    assert "<script>" not in res.sanitized_text
    assert "&lt;script&gt;" in res.sanitized_text
    assert "XSS_INJECTION" in res.violations


def test_canary_secret_leakage_blocked(filter_engine):
    leaked_output = "The internal token is CANARY-EXFILTRATION-CONFIDENTIAL."
    res = filter_engine.validate_and_sanitize(leaked_output)
    assert res.is_safe is False
    assert res.decision == SecurityDecision.BLOCKED
    assert "CANARY-" not in res.sanitized_text
    assert "CANARY_SECRET_LEAKAGE" in res.violations


def test_aviation_safety_disclaimer_appended(filter_engine):
    text = "Thrust opposes drag in flight."
    res = filter_engine.validate_and_sanitize(text, attach_disclaimer=True)
    assert AVIATION_SAFETY_DISCLAIMER in res.sanitized_text
