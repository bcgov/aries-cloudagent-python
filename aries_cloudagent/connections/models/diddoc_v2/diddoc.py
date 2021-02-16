"""
DID Document Class.

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

import logging
import copy
from typing import Union
from .verification_method import VerificationMethod
from .service import Service
from .schemas.diddocschema import DIDDocSchema
from ....resolver.did import DID_PATTERN, DIDUrl

LOGGER = logging.getLogger(__name__)


class DIDDoc:
    """
    DID document, grouping a DID with verification keys and services.

    Retains DIDs as raw values (orientated toward indy-facing operations),
    everything else as URIs (oriented toward W3C-facing operations).
    """

    CONTEXT = "https://w3id.org/did/v1"

    def __init__(
        self,
        id: str,
        also_known_as: list = None,
        controller=None,
        verification_method: list = None,
        authentication: list = None,
        assertion_method: list = None,
        key_agreement: list = None,
        capability_invocation: list = None,
        capability_delegation: list = None,
        public_key: list = None,
        service: list = None,
    ) -> None:

        """
        Initialize the DIDDoc instance.

        Retain DID ('id' in DIDDoc context); initialize verification keys
        and services to empty lists.

        Args:
            id: DIDDoc id.
            also_known_as: One or more other identifiers of the DIDDoc.
            controller: Contain verification relationships of the DIDDoc.
            verification_method: Specific verification method of the DIDDoc.
            authentication: Specific verification method of the DIDDoc.
            assertion_method: Specific verification method of the DIDDoc.
            key_agreement: Specific verification method of the DIDDoc.
            capability_invocation: Specific verification method of the DIDDoc.
            capability_delegation: Specific verification method of the DIDDoc.,
            public_key: Specific verification method of the DIDDoc.
            service: Communicating of the DID subject or associated entities.

        Raises:
            ValueError: for bad input DID.

        """
        # Validation process
        DIDDoc.validate_id(id)

        self._id = id
        self._also_known_as = also_known_as
        self._controller = controller
        self._index = {}
        self._ref_content = {}

        params = (
            ("verificationMethod", verification_method or []),
            ("authentication", authentication or []),
            ("assertionMethod", assertion_method or []),
            ("keyAgreement", key_agreement or []),
            ("capabilityInvocation", capability_invocation or []),
            ("capabilityDelegation", capability_delegation or []),
            ("publicKey", public_key or []),
            ("service", service or []),
        )

        for param in params:
            aux_content = []
            for item in param[1]:
                if not isinstance(item, str):
                    did_item = self._index.get(item)
                    if not self._index.get(item):
                        self._index[item.id] = item  # {id: <kind of param>}
                        aux_content.append(item.id)
                    else:
                        if not (did_item.serialize() == item.serialize()):
                            raise ValueError(
                                "{} has different specifications".format(item.id)
                            )
                else:
                    if not self._index.get(item):
                        self._index[item] = param[0]
                        aux_content.append(item.id)
            self._ref_content[param[0]] = aux_content

    @classmethod
    def validate_id(self, id):
        if not DID_PATTERN.match(id):
            raise ValueError("Not valid DID")

    @classmethod
    def deserialize(cls, json: dict):
        """
        Deserialize a dict into a DIDDoc object.

        Args:
            json: service or public key to set
        Returns: DIDDoc object
        """
        schema = DIDDocSchema()
        did_doc = schema.load(json)
        return did_doc

    def serialize(self) -> dict:
        """
        Serialize the DIDDoc object into dict.

        Returns: Dict
        """
        schema = DIDDocSchema()
        did_doc = schema.dump(copy.deepcopy(self))
        did_doc["@context"] = self.CONTEXT
        return did_doc

    @property
    def id(self) -> str:
        """
        Getter for DIDDoc id
        """
        return self._id

    @property
    def also_known_as(self):
        """
        Getter for DIDDoc alsoKnownAs
        """
        return self._also_known_as

    @property
    def controller(self):
        """
        Getter for DIDDoc controller
        """
        return self._controller

    @property
    def verification_method(self):
        """
        Getter for DIDDoc verificationMethod
        """
        aux_ids = []
        ids = self._ref_content.get("verificationMethod")
        for item in ids:
            aux_ids.append(self._index.get(item))
        return aux_ids

    @property
    def authentication(self):
        """
        Getter for DIDDoc authentication
        """
        aux_ids = []
        ids = self._ref_content.get("authentication")
        for item in ids:
            aux_ids.append(self._index.get(item))
        return aux_ids

    @property
    def assertion_method(self):
        """
        Getter for DIDDoc assertionMethod
        """
        aux_ids = []
        ids = self._ref_content.get("assertionMethod")
        for item in ids:
            aux_ids.append(self._index.get(item))
        return aux_ids

    @property
    def key_agreement(self):
        """
        Getter for DIDDoc keyAgreement
        """
        aux_ids = []
        ids = self._ref_content.get("keyAgreement")
        for item in ids:
            aux_ids.append(self._index.get(item))
        return aux_ids

    @property
    def capability_invocation(self):
        """
        Getter for DIDDoc capabilityInvocation
        """
        aux_ids = []
        ids = self._ref_content.get("capabilityInvocation")
        for item in ids:
            aux_ids.append(self._index.get(item))
        return aux_ids

    @property
    def capability_delegation(self):
        """
        Getter for DIDDoc capabilityDelegation
        """
        aux_ids = []
        ids = self._ref_content.get("capabilityDelegation")
        for item in ids:
            aux_ids.append(self._index.get(item))
        return aux_ids

    @property
    def public_key(self):
        """
        Getter for DIDDoc publicKey
        """
        aux_ids = []
        ids = self._ref_content.get("publicKey")
        for item in ids:
            aux_ids.append(self._index.get(item))
        return aux_ids

    @property
    def service(self):
        """
        Getter for DIDDoc service
        """
        aux_ids = []
        ids = self._ref_content.get("service")
        for item in ids:
            aux_ids.append(self._index.get(item))
        return aux_ids

    @id.setter
    def id(self, value: str) -> None:
        """
        Set DID ('id' in DIDDoc context).

        Args:
            value: id

        Raises:
            ValueError: for bad input DID.

        """

        # Validation process
        DIDDoc.validate_id(id)

        self._id = value

    def set(
        self,
        item: Union[Service, VerificationMethod],
        upsert=False,
        verification_type="publicKey",
    ) -> "DIDDoc":
        """
        Add or replace service or verification method; return current DIDDoc.
        Raises:
            ValueError: if input item is neither service nor public key.
        Args:
            item: service or public key to set
            upsert: True for overwrite if the ID exists
            verification_type: verification atribute choosen to insert the item
            if it is a verification method.
        Returns: None
        """

        # Verification did url
        DIDUrl.parse(item.id)

        # Upsert validation
        if self._index.get(item.id) and (not upsert):
            raise ValueError("ID already exists, use arg upsert to update it")

        self._index[item.id] = item

        if isinstance(item, Service):
            if item.id not in self._ref_content["service"]:
                self._ref_content["service"].append(item.id)
        else:
            if item.id not in self._ref_content[verification_type]:
                self._ref_content[verification_type].append(item.id)

    def dereference(self, did_url: str):
        """
        Retrieve a verification method or service by it id.
        Raises:
            ValueError: if input did_url is not good defined.
        Args:
            did_url: verification method or service id.
        """

        # Verification did url
        DIDUrl.parse(did_url)

        return self._index.get(did_url)
