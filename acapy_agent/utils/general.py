"""Utility functions for the admin server."""

import re
from hmac import compare_digest


def const_compare(string1, string2):
    """Compare two strings in constant time."""
    if string1 is None or string2 is None:
        return False
    return compare_digest(string1.encode(), string2.encode())


def strip_did_prefix(did: str) -> str | None:
    """Strip the DID prefix from a DID."""
    if did:
        return re.sub(r"^did:\w+:", "", did)
