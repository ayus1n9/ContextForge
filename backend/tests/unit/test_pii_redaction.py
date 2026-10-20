"""Unit Tests for PII Detection & Redaction Layer."""

import pytest
from backend.app.config import HandlingPolicy
from backend.app.observability.audit_logging import audit_logger
from backend.app.observability.security_events import SecurityDecision
from backend.app.security.pii_redaction import PIIRedactor, luhn_checksum_valid


@pytest.fixture
def redactor():
    return PIIRedactor()


def test_luhn_checksum():
    # Valid standard Visa test card number
    assert luhn_checksum_valid("4532015012345671") is True
    # Invalid card number
    assert luhn_checksum_valid("4532015012345679") is False


def test_email_redaction(redactor):
    text = "Send telemetry report to engineer.sarah@nasa.gov for review."
    res = redactor.process(text, policy=HandlingPolicy.REDACT)
    assert res.has_pii is True
    assert "EMAIL" in res.detected_types
    assert "engineer.sarah@nasa.gov" not in res.redacted_text
    assert "[REDACTED_EMAIL]" in res.redacted_text
    assert res.decision == SecurityDecision.REDACTED


def test_phone_redaction(redactor):
    text = "Contact flight dispatch at (555) 839-2019 immediately."
    res = redactor.process(text, policy=HandlingPolicy.REDACT)
    assert res.has_pii is True
    assert "PHONE" in res.detected_types
    assert "(555) 839-2019" not in res.redacted_text
    assert "[REDACTED_PHONE]" in res.redacted_text


def test_ssn_redaction(redactor):
    text = "Pilot identification check with SSN: 123-45-6789."
    res = redactor.process(text, policy=HandlingPolicy.REDACT)
    assert res.has_pii is True
    assert "SSN" in res.detected_types
    assert "123-45-6789" not in res.redacted_text
    assert "[REDACTED_SSN]" in res.redacted_text


def test_canary_secret_redaction(redactor):
    text = "Internal token is CANARY-SECRET-VAULT-2026."
    res = redactor.process(text, policy=HandlingPolicy.REDACT)
    assert res.has_pii is True
    assert "SECRET_KEY" in res.detected_types
    assert "CANARY-SECRET-VAULT-2026" not in res.redacted_text
    assert "[REDACTED_SECRET]" in res.redacted_text


def test_block_policy(redactor):
    text = "User email is admin@example.com."
    res = redactor.process(text, policy=HandlingPolicy.BLOCK)
    assert res.has_pii is True
    assert res.decision == SecurityDecision.BLOCKED


def test_allow_policy(redactor):
    text = "User email is admin@example.com."
    res = redactor.process(text, policy=HandlingPolicy.ALLOW)
    assert res.has_pii is True
    assert res.decision == SecurityDecision.ALLOWED
    assert "admin@example.com" in res.redacted_text


def test_audit_log_never_contains_raw_secrets(redactor):
    canary = "CANARY-SUPER-SECRET-PAYLOAD-999"
    redactor.process(f"Test with {canary}", policy=HandlingPolicy.REDACT)
    recent = audit_logger.get_recent_events(limit=5)
    for evt in recent:
        dumped = evt.model_dump_json()
        assert canary not in dumped
