"""Test did:web Resolver."""

import pytest
from ..web import WebDIDResolver


@pytest.fixture
def resolver():
    yield WebDIDResolver()


@pytest.fixture
def profile():
    yield None


def test_transformation_domain_only(resolver):
    did = "did:web:example.com"
    url = resolver._WebDIDResolver__transform_to_url(did)
    assert url == "https://example.com/.well-known/did.json"


def test_transformation_domain_with_path(resolver):
    did = "did:web:example.com:department:example"
    url = resolver._WebDIDResolver__transform_to_url(did)
    assert url == "https://example.com/department/example/did.json"
