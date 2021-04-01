"""
DIDDoc utility methods.

Copyright 2017-2019 Government of Canada
Public Services and Procurement Canada - buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


from base58 import b58decode
from urllib.parse import urlparse


def resource(ref: str, delimiter: str = None) -> str:
    """
    Extract the resource for an identifier.

    Given a (URI) reference, return up to its delimiter (exclusively), or all of it if
    there is none.

    Args:
        ref: reference
        delimiter: delimiter character
            (default None maps to '#', or ';' introduces identifiers)
    """

    return ref.split(delimiter if delimiter else "#")[0]


def canon_ref(did: str, ref: str, delimiter: str = None):
    """
    Given a reference in a DID document, return it in its canonical form of a URI.

    Args:
        did: DID acting as the identifier of the DID document
        ref: reference to canonicalize, either a DID or a fragment pointing to a
            location in the DID doc
        delimiter: delimiter character marking fragment (default '#') or
            introducing identifier (';') against DID resource
    """

    if (
        ref.startswith("did:")
        or urlparse(ref).scheme  # e.g., https://example.com/messages/8377464
    ):
        return ref

    return "{}{}{}".format(did, delimiter if delimiter else "#", ref)


def ok_did(token: str) -> bool:
    """
    Whether input token looks like a valid decentralized identifier.

    Args:
        token: candidate string

    Returns: whether input token looks like a valid schema identifier

    """

    try:
        return len(b58decode(token)) == 16 if token else False
    except ValueError:
        return False
