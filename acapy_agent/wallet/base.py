"""Wallet base class."""

from abc import ABC, abstractmethod
from typing import List, Optional, Sequence, Tuple, Union

from ..ledger.base import BaseLedger
from ..ledger.endpoint_type import EndpointType
from .did_info import DIDInfo, KeyInfo
from .did_method import SOV, DIDMethod
from .error import WalletError
from .key_type import KeyType


class BaseWallet(ABC):
    """Abstract wallet interface."""

    @abstractmethod
    async def create_signing_key(
        self,
        key_type: KeyType,
        seed: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> KeyInfo:
        """Create a new public/private signing keypair.

        Args:
            key_type: Key type to create
            seed: Optional seed allowing deterministic key creation
            metadata: Optional metadata to store with the keypair

        Returns:
            A `KeyInfo` representing the new record

        """

    @abstractmethod
    async def create_key(
        self,
        key_type: KeyType,
        seed: Optional[str] = None,
        metadata: Optional[dict] = None,
        kid: Optional[str] = None,
    ) -> KeyInfo:
        """Create a new public/private keypair.

        Args:
            key_type: Key type to create
            seed: Seed for key
            metadata: Optional metadata to store with the keypair
            kid: Optional key identifier

        Returns:
            A `KeyInfo` representing the new record

        Raises:
            WalletDuplicateError: If the resulting verkey already exists in the wallet
            WalletError: If there is another backend error
        """

    @abstractmethod
    async def assign_kid_to_key(self, verkey: str, kid: str) -> KeyInfo:
        """Assign a KID to a key.

        This is separate from the create_key method because some DIDs are only
        known after keys are created.

        Args:
            verkey: The verification key of the keypair
            kid: The kid to assign to the keypair

        Returns:
            A `KeyInfo` representing the keypair

        """

    @abstractmethod
    async def get_key_by_kid(self, kid: str) -> KeyInfo:
        """Fetch a key by looking up its kid.

        Args:
            kid: the key identifier

        Returns:
            The key identified by kid

        """

    @abstractmethod
    async def get_signing_key(self, verkey: str) -> KeyInfo:
        """Fetch info for a signing keypair.

        Args:
            verkey: The verification key of the keypair

        Returns:
            A `KeyInfo` representing the keypair

        """

    @abstractmethod
    async def replace_signing_key_metadata(self, verkey: str, metadata: dict):
        """Replace the metadata associated with a signing keypair.

        Args:
            verkey: The verification key of the keypair
            metadata: The new metadata to store

        """

    @abstractmethod
    async def rotate_did_keypair_start(
        self, did: str, next_seed: Optional[str] = None
    ) -> str:
        """Begin key rotation for DID that wallet owns: generate new keypair.

        Args:
            did: signing DID
            next_seed: seed for incoming ed25519 key pair (default random)

        Returns:
            The new verification key

        Raises:
            WalletNotFoundError: if wallet does not own DID

        """

    @abstractmethod
    async def rotate_did_keypair_apply(self, did: str) -> None:
        """Apply temporary keypair as main for DID that wallet owns.

        Args:
            did: signing DID

        Raises:
            WalletNotFoundError: if wallet does not own DID
            WalletError: if wallet has not started key rotation

        """

    @abstractmethod
    async def create_local_did(
        self,
        method: DIDMethod,
        key_type: KeyType,
        seed: Optional[str] = None,
        did: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> DIDInfo:
        """Create and store a new local DID.

        Args:
            method: The method to use for the DID
            key_type: The key type to use for the DID
            seed: Optional seed to use for DID
            did: The DID to use
            metadata: Metadata to store with DID

        Returns:
            The created `DIDInfo`

        """

    @abstractmethod
    async def store_did(self, did_info: DIDInfo) -> DIDInfo:
        """Store a DID in the wallet.

        This enables components external to the wallet to define how a DID
        is created and then store it in the wallet for later use.

        Args:
            did_info: The DID to store

        Returns:
            The stored `DIDInfo`
        """

    async def create_public_did(
        self,
        method: DIDMethod,
        key_type: KeyType,
        seed: Optional[str] = None,
        did: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> DIDInfo:
        """Create and store a new public DID.

        This method creates a new public DID using the specified DID method and key type.

        The optional `seed` parameter can be used to provide a seed for the DID
            generation.

        If a `did` is provided, it will be used as the DID instead of generating a new
            one.

        The `metadata` parameter can be used to store additional metadata with the DID.

        Args:
            method: The DID method to use for creating the DID.
            key_type: The key type to use for the DID.
            seed: Optional seed to use for DID generation.
            did: The DID to use instead of generating a new one.
            metadata: Optional metadata to store with the DID.

        Returns:
            The created `DIDInfo` object.

        """
        metadata = metadata or {}
        metadata.setdefault("posted", True)
        did_info = await self.create_local_did(
            method=method, key_type=key_type, seed=seed, did=did, metadata=metadata
        )
        return await self.set_public_did(did_info)

    @abstractmethod
    async def get_public_did(self) -> DIDInfo | None:
        """Retrieve the public DID.

        Returns:
            The currently public `DIDInfo`, if any

        """

    @abstractmethod
    async def set_public_did(self, did: Union[str, DIDInfo]) -> DIDInfo:
        """Assign the public DID.

        Returns:
            The updated `DIDInfo`

        """

    @abstractmethod
    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """Get list of defined local DIDs.

        Returns:
            A list of `DIDInfo` instances

        """

    @abstractmethod
    async def get_local_did(self, did: str) -> DIDInfo:
        """Find info for a local DID.

        Args:
            did: The DID for which to get info

        Returns:
            A `DIDInfo` instance for the DID

        """

    @abstractmethod
    async def get_local_did_for_verkey(self, verkey: str) -> DIDInfo:
        """Resolve a local DID from a verkey.

        Args:
            verkey: Verkey for which to get DID info

        Returns:
            A `DIDInfo` instance for the DID

        """

    @abstractmethod
    async def replace_local_did_metadata(self, did: str, metadata: dict):
        """Replace the metadata associated with a local DID.

        Prefer `set_did_endpoint()` to set endpoint in metadata.

        Args:
            did: DID for which to replace metadata
            metadata: The new metadata

        """

    async def get_posted_dids(self) -> Sequence[DIDInfo]:
        """Get list of defined posted DIDs.

        Returns:
            A list of `DIDInfo` instances

        """
        return [
            info for info in await self.get_local_dids() if info.metadata.get("posted")
        ]

    async def set_did_endpoint(
        self,
        did: str,
        endpoint: str,
        _ledger: BaseLedger,
        endpoint_type: Optional[EndpointType] = None,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
        routing_keys: Optional[List[str]] = None,
    ):
        """Update the endpoint for a DID in the wallet, send to ledger if posted.

        Args:
            did (str): The DID for which to set the endpoint.
            endpoint (str): The endpoint to set. Use None to clear the endpoint.
            _ledger (BaseLedger): The ledger to which to send the endpoint update if the
                DID is public or posted.
            endpoint_type (EndpointType, optional): The type of the endpoint/service.
                Only endpoint_type 'endpoint' affects the local wallet.
            write_ledger (bool, optional): Whether to write the endpoint update to the
                ledger. Defaults to True.
            endorser_did (str, optional): The DID of the endorser. Defaults to None.
            routing_keys (List[str], optional): The list of routing keys.
                Defaults to None.

        Raises:
            WalletError: If the DID method is not 'did:sov'.

        """
        did_info = await self.get_local_did(did)

        if did_info.method != SOV:
            raise WalletError("Setting DID endpoint is only allowed for did:sov DIDs")
        metadata = {**did_info.metadata}
        if not endpoint_type:
            endpoint_type = EndpointType.ENDPOINT
        if endpoint_type == EndpointType.ENDPOINT:
            metadata[endpoint_type.indy] = endpoint

        await self.replace_local_did_metadata(did, metadata)

    @abstractmethod
    async def sign_message(
        self, message: Union[List[bytes], bytes], from_verkey: str
    ) -> bytes:
        """Sign message(s) using the private key associated with a given verkey.

        Args:
            message: The message(s) to sign
            from_verkey: Sign using the private key related to this verkey

        Returns:
            The signature

        """

    @abstractmethod
    async def verify_message(
        self,
        message: Union[List[bytes], bytes],
        signature: bytes,
        from_verkey: str,
        key_type: KeyType,
    ) -> bool:
        """Verify a signature against the public key of the signer.

        Args:
            message: The message to verify
            signature: The signature to verify
            from_verkey: Verkey to use in verification
            key_type: The key type to derive the signature verification algorithm from

        Returns:
            True if verified, else False

        """

    @abstractmethod
    async def pack_message(
        self, message: str, to_verkeys: Sequence[str], from_verkey: Optional[str] = None
    ) -> bytes:
        """Pack a message for one or more recipients.

        Args:
            message: The message to pack
            to_verkeys: The verkeys to pack the message for
            from_verkey: The sender verkey

        Returns:
            The packed message

        """

    @abstractmethod
    async def unpack_message(self, enc_message: bytes) -> Tuple[str, str, str]:
        """Unpack a message.

        Args:
            enc_message: The encrypted message

        Returns:
            A tuple: (message, from_verkey, to_verkey)

        """

    def __repr__(self) -> str:
        """Get a human readable string."""
        return "<{}>".format(self.__class__.__name__)
