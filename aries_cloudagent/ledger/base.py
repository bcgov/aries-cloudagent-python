"""Ledger base class."""

import re

from abc import ABC, abstractmethod, ABCMeta
from enum import Enum
from typing import Sequence, Tuple, Union

from ..indy.issuer import IndyIssuer
from ..utils import sentinel
from ..wallet.did_info import DIDInfo

from .endpoint_type import EndpointType


class BaseLedger(ABC, metaclass=ABCMeta):
    """Base class for ledger."""

    BACKEND_NAME = None

    async def __aenter__(self) -> "BaseLedger":
        """
        Context manager entry.

        Returns:
            The current instance

        """
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Context manager exit."""

    @property
    def backend(self) -> str:
        """Accessor for the ledger backend name."""
        return self.__class__.BACKEND_NAME

    @property
    @abstractmethod
    def read_only(self) -> bool:
        """Accessor for the ledger read-only flag."""

    @abstractmethod
    async def get_key_for_did(self, did: str) -> str:
        """Fetch the verkey for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
        """

    @abstractmethod
    async def get_endpoint_for_did(
        self, did: str, endpoint_type: EndpointType = EndpointType.ENDPOINT
    ) -> str:
        """Fetch the endpoint for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
            endpoint_type: The type of the endpoint (default 'endpoint')
        """

    @abstractmethod
    async def update_endpoint_for_did(
        self,
        did: str,
        endpoint: str,
        endpoint_type: EndpointType = EndpointType.ENDPOINT,
    ) -> bool:
        """Check and update the endpoint on the ledger.

        Args:
            did: The ledger DID
            endpoint: The endpoint address
            endpoint_type: The type of the endpoint (default 'endpoint')
        """

    @abstractmethod
    async def register_nym(
        self, did: str, verkey: str, alias: str = None, role: str = None
    ):
        """
        Register a nym on the ledger.

        Args:
            did: DID to register on the ledger.
            verkey: The verification key of the keypair.
            alias: Human-friendly alias to assign to the DID.
            role: For permissioned ledgers, what role should the new DID have.
        """

    @abstractmethod
    async def get_nym_role(self, did: str):
        """
        Return the role registered to input public DID on the ledger.

        Args:
            did: DID to register on the ledger.
        """

    @abstractmethod
    def nym_to_did(self, nym: str) -> str:
        """Format a nym with the ledger's DID prefix."""

    @abstractmethod
    async def rotate_public_did_keypair(self, next_seed: str = None) -> None:
        """
        Rotate keypair for public DID: create new key, submit to ledger, update wallet.

        Args:
            next_seed: seed for incoming ed25519 keypair (default random)
        """

    def did_to_nym(self, did: str) -> str:
        """Remove the ledger's DID prefix to produce a nym."""
        if did:
            return re.sub(r"^did:\w+:", "", did)

    async def get_txn_author_agreement(self, reload: bool = False):
        """Get the current transaction author agreement, fetching it if necessary."""

    async def fetch_txn_author_agreement(self):
        """Fetch the current AML and TAA from the ledger."""

    async def accept_txn_author_agreement(
        self, taa_record: dict, mechanism: str, accept_time: int = None
    ):
        """Save a new record recording the acceptance of the TAA."""

    async def get_latest_txn_author_acceptance(self):
        """Look up the latest TAA acceptance."""

    def taa_digest(self, version: str, text: str):
        """Generate the digest of a TAA record."""

    @abstractmethod
    async def txn_endorse(
        self,
        request_json: str,
    ) -> str:
        """Endorse (sign) the provided transaction."""

    @abstractmethod
    async def txn_submit(
        self,
        request_json: str,
        sign: bool,
        taa_accept: bool,
        sign_did: DIDInfo = sentinel,
    ) -> str:
        """Write the provided (signed and possibly endorsed) transaction to the ledger."""

    @abstractmethod
    async def create_and_send_schema(
        self,
        issuer: IndyIssuer,
        schema_name: str,
        schema_version: str,
        attribute_names: Sequence[str],
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> Tuple[str, dict]:
        """
        Send schema to ledger.

        Args:
            issuer: The issuer instance to use for schema creation
            schema_name: The schema name
            schema_version: The schema version
            attribute_names: A list of schema attributes

        """

    @abstractmethod
    async def get_revoc_reg_def(self, revoc_reg_id: str) -> dict:
        """Look up a revocation registry definition by ID."""

    @abstractmethod
    async def send_revoc_reg_def(self, revoc_reg_def: dict, issuer_did: str = None):
        """Publish a revocation registry definition to the ledger."""

    @abstractmethod
    async def send_revoc_reg_entry(
        self,
        revoc_reg_id: str,
        revoc_def_type: str,
        revoc_reg_entry: dict,
        issuer_did: str = None,
    ):
        """Publish a revocation registry entry to the ledger."""

    @abstractmethod
    async def create_and_send_credential_definition(
        self,
        issuer: IndyIssuer,
        schema_id: str,
        signature_type: str = None,
        tag: str = None,
        support_revocation: bool = False,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> Tuple[str, dict, bool]:
        """
        Send credential definition to ledger and store relevant key matter in wallet.

        Args:
            issuer: The issuer instance to use for credential definition creation
            schema_id: The schema id of the schema to create cred def for
            signature_type: The signature type to use on the credential definition
            tag: Optional tag to distinguish multiple credential definitions
            support_revocation: Optional flag to enable revocation for this cred def

        Returns:
            Tuple with cred def id, cred def structure, and whether it's novel

        """

    @abstractmethod
    async def get_credential_definition(self, credential_definition_id: str) -> dict:
        """
        Get a credential definition from the cache if available, otherwise the ledger.

        Args:
            credential_definition_id: The schema id of the schema to fetch cred def for

        """

    @abstractmethod
    async def get_revoc_reg_delta(
        self, revoc_reg_id: str, timestamp_from=0, timestamp_to=None
    ) -> Tuple[dict, int]:
        """Look up a revocation registry delta by ID."""

    @abstractmethod
    async def get_schema(self, schema_id: str) -> dict:
        """
        Get a schema from the cache if available, otherwise fetch from the ledger.

        Args:
            schema_id: The schema id (or stringified sequence number) to retrieve

        """

    @abstractmethod
    async def get_revoc_reg_entry(
        self, revoc_reg_id: str, timestamp: int
    ) -> Tuple[dict, int]:
        """Get revocation registry entry by revocation registry ID and timestamp."""


class Role(Enum):
    """Enum for indy roles."""

    STEWARD = (2,)
    TRUSTEE = (0,)
    ENDORSER = (101,)
    NETWORK_MONITOR = (201,)
    USER = (None, "")  # in case reading from file, default empty "" or None for USER
    ROLE_REMOVE = ("",)  # but indy-sdk uses "" to identify a role in reset

    @staticmethod
    def get(token: Union[str, int] = None) -> "Role":
        """
        Return enum instance corresponding to input token.

        Args:
            token: token identifying role to indy-sdk:
                "STEWARD", "TRUSTEE", "ENDORSER", "" or None
        """
        if token is None:
            return Role.USER

        for role in Role:
            if role == Role.ROLE_REMOVE:
                continue  # not a sensible role to parse from any configuration
            if isinstance(token, int) and token in role.value:
                return role
            if str(token).upper() == role.name or token in (str(v) for v in role.value):
                return role

        return None

    def to_indy_num_str(self) -> str:
        """
        Return (typically, numeric) string value that indy-sdk associates with role.

        Recall that None signifies USER and "" signifies a role undergoing reset.
        """

        return str(self.value[0]) if isinstance(self.value[0], int) else self.value[0]

    def token(self) -> str:
        """Return token identifying role to indy-sdk."""

        return self.value[0] if self in (Role.USER, Role.ROLE_REMOVE) else self.name
