"""
DID Document classes.

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


import json
import logging

from typing import List, Sequence, Union

from .publickey import PublicKey, PublicKeyType
from .service import Service
from .util import canon_ref

LOGGER = logging.getLogger(__name__)


def _parseError(msg: str):
    LOGGER.debug(msg)
    raise ValueError(msg)


class DIDDoc:
    """
    DID document, grouping a DID with verification keys and services.

    Retains DIDs as raw values (orientated toward indy-facing operations),
    everything else as URIs (oriented toward W3C-facing operations).
    """

    CONTEXT_V0 = "https://w3id.org/did/v1"
    CONTEXT_V1 = "https://www.w3.org/ns/did/v1"

    SERVICE_TYPE_V0 = "IndyAgent"
    SERVICE_TYPE_V1 = "did-communication"

    def __init__(self, did: str = None) -> None:
        """
        Initialize the DIDDoc instance.

        Retain DID ('id' in DIDDoc context); initialize verification keys
        and services to empty lists.

        Args:
            did: DID for current DIDdoc

        Raises:
            ValueError: for bad input DID.

        """

        self._did = did
        self._pubkey = {}
        self._service = {}

    @property
    def did(self) -> str:
        """Accessor for DID."""

        return self._did

    @did.setter
    def did(self, value: str) -> None:
        """
        Set DID ('id' in DIDDoc context).

        Args:
            value: DID

        Raises:
            ValueError: for bad input DID.

        """

        self._did = value

    @property
    def pubkey(self) -> dict:
        """Accessor for public keys by identifier."""

        return self._pubkey

    @property
    def authnkey(self) -> dict:
        """Accessor for public keys marked as authentication keys, by identifier."""

        return {k: self._pubkey[k] for k in self._pubkey if self._pubkey[k].authn}

    @property
    def service(self) -> dict:
        """Accessor for services by identifier."""

        return self._service

    def set(self, item: Union[Service, PublicKey]) -> "DIDDoc":
        """
        Add or replace service or public key; return current DIDDoc.

        Raises:
            ValueError: if input item is neither service nor public key.

        Args:
            item: service or public key to set

        Returns: the current DIDDoc

        """

        if isinstance(item, Service):
            self.service[item.id] = item
        elif isinstance(item, PublicKey):
            self.pubkey[item.id] = item
        else:
            raise ValueError(
                "Cannot add item {} to DIDDoc on DID {}".format(item, self.did)
            )

    def serialize(self, *, version: int = 0) -> dict:
        """
        Dump current object to a JSON-compatible dictionary.

        Args:
            version: Define the version of the spec to use in serialization

        Returns:
            dict representation of current DIDDoc

        """

        if version == 0:
            return {
                "@context": DIDDoc.CONTEXT_V0,
                "id": self.did,
                "publicKey": [pubkey.to_dict() for pubkey in self.pubkey.values()],
                "authentication": [
                    {
                        "type": pubkey.type.authn_type,
                        "publicKey": canon_ref(self.did, pubkey.id),
                    }
                    for pubkey in self.pubkey.values()
                    if pubkey.authn
                ],
                "service": [service.to_dict() for service in self.service.values()],
            }
        elif version == 1:
            return {
                "@context": DIDDoc.CONTEXT_V1,
                "id": self.did,
                "verificationMethod": [
                    pubkey.to_dict() for pubkey in self.pubkey.values()
                ],
                "authentication": [
                    pubkey.id for pubkey in self.pubkey.values() if pubkey.authn
                ],
                "service": [service.to_dict() for service in self.service.values()],
            }
        else:
            raise ValueError(f"Unsupported version for serialization: {version}")

    def to_json(self) -> str:
        """
        Dump current object as json (JSON-LD).

        Returns:
            json representation of current DIDDoc

        """

        return json.dumps(self.serialize())

    def add_service_pubkeys(
        self, service: dict, tags: Union[Sequence[str], str]
    ) -> List[PublicKey]:
        """
        Add public keys specified in service. Return public keys so discovered.

        Args:
            service: service from DID document
            tags: potential tags marking public keys of type of interest
                (the standard is still coalescing)

        Raises:
            ValueError: for public key reference not present in DID document.

        Returns: list of public keys from the document service specification

        """

        rv = []
        for tag in [tags] if isinstance(tags, str) else list(tags):

            for svc_key in service.get(tag, {}):
                canon_key = canon_ref(self.did, svc_key)
                pubkey = None

                if "#" in svc_key:
                    if canon_key in self.pubkey:
                        pubkey = self.pubkey[canon_key]
                    else:  # service key refers to another DID doc
                        LOGGER.debug(
                            "DID document %s has no public key %s", self.did, svc_key
                        )
                        raise ValueError(
                            "DID document {} has no public key {}".format(
                                self.did, svc_key
                            )
                        )
                else:
                    for existing_pubkey in self.pubkey.values():
                        if existing_pubkey.value == svc_key:
                            pubkey = existing_pubkey
                            break
                    else:
                        pubkey = PublicKey(
                            self.did,
                            ident=svc_key[-9:-1],  # industrial-grade uniqueness
                            value=svc_key,
                        )
                        self._pubkey[pubkey.id] = pubkey

                if (
                    pubkey and pubkey not in rv
                ):  # perverse case: could specify same key multiple ways; append once
                    rv.append(pubkey)

        return rv

    @classmethod
    def deserialize(cls, did_doc: dict) -> "DIDDoc":
        """
        Construct DIDDoc object from dict representation.

        Args:
            did_doc: DIDDoc dict representation

        Raises:
            ValueError: for bad DID or missing mandatory item.

        Returns: DIDDoc from input json

        """

        if "id" not in did_doc:
            _parseError("no identifier in DID document")

        rv = DIDDoc(did_doc["id"])

        auth_key_ids = set()
        for akey in did_doc.get(
            "authentication", {}
        ):  # include embedded authentication keys
            if isinstance(akey, str):
                auth_key_ids.add(canon_ref(rv.did, akey))
            elif "publicKey" in akey:
                # v0 representation
                auth_key_ids.add(canon_ref(rv.did, akey["publicKey"]))
            else:
                pubkey_type = PublicKeyType.get(akey["type"])
                key = PublicKey(  # initialization canonicalized id
                    rv.did,
                    akey["id"],
                    akey[pubkey_type.specifier],
                    pubkey_type,
                    akey["controller"],
                    True,
                )
                if key.id in rv.pubkey:
                    _parseError(f"duplicate key id: {key.id}")
                rv.pubkey[key.id] = key

        pubkeys = did_doc.get("verificationMethod", did_doc.get("publicKey")) or {}
        for (
            pubkey
        ) in pubkeys:  # include all public keys, authentication pubkeys by reference
            pubkey_type = PublicKeyType.get(pubkey["type"])
            key = PublicKey(  # initialization canonicalizes id
                rv.did,
                pubkey["id"],
                pubkey[pubkey_type.specifier],
                pubkey_type,
                pubkey["controller"],
                False,
            )
            if key.id in auth_key_ids:
                key.authn = True
            if key.id in rv.pubkey:
                _parseError(f"duplicate key id: {key.id}")
            rv.pubkey[key.id] = key

        for service in did_doc.get("service", {}):
            endpoint = service["serviceEndpoint"]
            svc = Service(  # initialization canonicalizes id
                rv.did,
                service.get(
                    "id",
                    canon_ref(
                        rv.did, "assigned-service-{}".format(len(rv.service)), ";"
                    ),
                ),
                service["type"],
                rv.add_service_pubkeys(service, "recipientKeys"),
                rv.add_service_pubkeys(service, ["mediatorKeys", "routingKeys"]),
                canon_ref(rv.did, endpoint, ";") if ";" in endpoint else endpoint,
                service.get("priority", None),
            )
            rv.service[svc.id] = svc

        return rv

    @classmethod
    def from_json(cls, did_doc_json: str) -> "DIDDoc":
        """
        Construct DIDDoc object from json representation.

        Args:
            did_doc_json: DIDDoc json representation

        Returns: DIDDoc from input json

        """

        return cls.deserialize(json.loads(did_doc_json))

    def __str__(self) -> str:
        """Return string representation for abbreviated display."""

        return f"DIDDoc({self.did})"

    def __repr__(self) -> str:
        """Format DIDDoc for logging."""

        return f"<DIDDoc did={self.did}>"
