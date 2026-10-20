"""Unit Tests for Input Validation Layer."""

import pytest
from backend.app.security.input_validation import input_validator


def test_valid_query():
    valid, err = input_validator.validate_query("What are the primary flight controls of an airplane?")
    assert valid is True
    assert err is None


def test_empty_query_rejected():
    valid, err = input_validator.validate_query("   \t  \n  ")
    assert valid is False
    assert "empty" in err.lower()


def test_oversized_query_rejected():
    oversized = "A" * 2500
    valid, err = input_validator.validate_query(oversized)
    assert valid is False
    assert "exceeds maximum length" in err.lower()


def test_null_byte_rejected():
    null_byte_query = "What is lift?\x00and how does it work?"
    valid, err = input_validator.validate_query(null_byte_query)
    assert valid is False
    assert "null byte" in err.lower()


def test_control_characters_rejected():
    control_char_query = "What is thrust?\x07\x08"
    valid, err = input_validator.validate_query(control_char_query)
    assert valid is False
    assert "control characters" in err.lower()


def test_non_string_input_rejected():
    valid, err = input_validator.validate_query(12345)  # type: ignore
    assert valid is False
    assert "string" in err.lower()
