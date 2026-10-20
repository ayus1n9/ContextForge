"""Unit Tests for Retrieval Authorization and Access Control Layer."""

import pytest
from backend.app.observability.security_events import SecurityDecision
from backend.app.security.access_control import (
    AccessControlEnforcer,
    DocumentClassification,
    UserContext,
)


@pytest.fixture
def acl():
    return AccessControlEnforcer()


def test_public_user_accesses_public_doc(acl):
    user = UserContext(user_id="user1", roles=["viewer"], clearance=DocumentClassification.PUBLIC)
    meta = {"doc_id": "doc-public", "classification": "PUBLIC"}
    assert acl.can_access_document(user, meta) is True


def test_public_user_denied_restricted_doc(acl):
    user = UserContext(user_id="user1", roles=["viewer"], clearance=DocumentClassification.PUBLIC)
    meta = {"doc_id": "doc-secret", "classification": "RESTRICTED"}
    assert acl.can_access_document(user, meta) is False


def test_internal_user_denied_restricted_doc(acl):
    user = UserContext(user_id="user2", roles=["engineer"], clearance=DocumentClassification.INTERNAL)
    meta = {"doc_id": "doc-classified", "classification": "RESTRICTED"}
    assert acl.can_access_document(user, meta) is False


def test_admin_accesses_restricted_doc(acl):
    user = UserContext(user_id="admin_user", roles=["admin"], clearance=DocumentClassification.RESTRICTED)
    meta = {"doc_id": "doc-classified", "classification": "RESTRICTED", "allowed_roles": ["admin"]}
    assert acl.can_access_document(user, meta) is True


def test_role_mismatch_denied(acl):
    user = UserContext(user_id="user3", roles=["viewer"], clearance=DocumentClassification.RESTRICTED)
    meta = {"doc_id": "doc-classified", "classification": "RESTRICTED", "allowed_roles": ["engineer"]}
    assert acl.can_access_document(user, meta) is False


def test_filter_chunks(acl):
    user = UserContext(user_id="user1", roles=["viewer"], clearance=DocumentClassification.PUBLIC)
    chunks = [
        {"chunk_id": "c1", "text": "public info", "metadata": {"doc_id": "d1", "classification": "PUBLIC"}},
        {"chunk_id": "c2", "text": "secret info", "metadata": {"doc_id": "d2", "classification": "RESTRICTED"}},
    ]
    filtered = acl.filter_chunks(chunks, user)
    assert len(filtered) == 1
    assert filtered[0]["chunk_id"] == "c1"
