"""Aries-Askar implementation of BaseWallet interface."""

import json
import logging

from typing import Sequence

from aries_askar import (
    derive_verkey,
    verify_signature,
    KeyAlg,
    Session,
    StoreError,
    StoreErrorCode,
)

from ..askar.profile import AskarProfileSession
from ..ledger.base import BaseLedger
from ..ledger.endpoint_type import EndpointType
from ..ledger.error import LedgerConfigError

from .base import BaseWallet, KeyInfo, DIDInfo
from .crypto import validate_seed
from .error import WalletError, WalletDuplicateError, WalletNotFoundError
from .util import b58_to_bytes, bytes_to_b58

CATEGORY_DID = "did"

LOGGER = logging.getLogger(__name__)


# it would be nice for aca-py to handle qualified verkeys in general
def normalize_verkey(verkey: str):
    """Strip key algorithm suffix from verkey."""

    return verkey.replace(":ed25519", "")


class AskarWallet(BaseWallet):
    """Aries-Askar wallet implementation."""

    def __init__(self, session: AskarProfileSession):
        """
        Initialize a new `AskarWallet` instance.

        Args:
            session: The Askar profile session instance to use
        """
        self._session = session

    @property
    def session(self) -> Session:
        """Accessor for Askar profile session instance."""
        return self._session

    async def create_signing_key(
        self, seed: str = None, metadata: dict = None
    ) -> KeyInfo:
        """
        Create a new public/private signing keypair.

        Args:
            seed: Seed for key
            metadata: Optional metadata to store with the keypair

        Returns:
            A `KeyInfo` representing the new record

        Raises:
            WalletDuplicateError: If the resulting verkey already exists in the wallet
            WalletError: If there is a libindy error

        """

        if metadata is None:
            metadata = {}
        try:
            verkey = await self._session.handle.create_keypair(
                KeyAlg.ED25519,
                metadata=json.dumps(metadata),
                seed=validate_seed(seed),
            )
        except StoreError as err:
            if err.code == StoreErrorCode.DUPLICATE:
                raise WalletDuplicateError(
                    "Verification key already present in wallet"
                ) from None
            raise WalletError("Error creating signing key") from err

        return KeyInfo(normalize_verkey(verkey), metadata)

    async def get_signing_key(self, verkey: str) -> KeyInfo:
        """
        Fetch info for a signing keypair.

        Args:
            verkey: The verification key of the keypair

        Returns:
            A `KeyInfo` representing the keypair

        Raises:
            WalletNotFoundError: If no keypair is associated with the verification key
            WalletError: If there is a libindy error

        """

        if not verkey:
            raise WalletNotFoundError("No key identifier provided")
        key = await self._session.handle.fetch_keypair(verkey)
        if not key:
            raise WalletNotFoundError("Unknown key: {}".format(verkey))
        meta = json.loads(key.params.get("meta") or "{}")
        return KeyInfo(verkey, meta)

    async def replace_signing_key_metadata(self, verkey: str, metadata: dict):
        """
        Replace the metadata associated with a signing keypair.

        Args:
            verkey: The verification key of the keypair
            metadata: The new metadata to store

        Raises:
            WalletNotFoundError: if no keypair is associated with the verification key

        """

        # FIXME uses should always create a transaction first

        if not verkey:
            raise WalletNotFoundError("No key identifier provided")

        key = await self._session.handle.fetch_keypair(verkey, for_update=True)
        if not key:
            raise WalletNotFoundError("Keypair not found")
        await self._session.handle.update_keypair(
            verkey, metadata=json.dumps(metadata or {}), tags=key.tags
        )

    async def create_local_did(
        self, seed: str = None, did: str = None, metadata: dict = None
    ) -> DIDInfo:
        """
        Create and store a new local DID.

        Args:
            seed: Optional seed to use for DID
            did: The DID to use
            metadata: Metadata to store with DID

        Returns:
            A `DIDInfo` instance representing the created DID

        Raises:
            WalletDuplicateError: If the DID already exists in the wallet
            WalletError: If there is a libindy error

        """

        if not metadata:
            metadata = {}

        try:
            if seed:
                # create a key from a seed
                seed = validate_seed(seed)
                try:
                    verkey = await self._session.handle.create_keypair(
                        KeyAlg.ED25519, seed=seed
                    )
                except StoreError as err:
                    if err.code == StoreErrorCode.DUPLICATE:
                        verkey = await derive_verkey(KeyAlg.ED25519, seed)
                    else:
                        raise WalletError(
                            "Error when creating keypair for local DID"
                        ) from err
            else:
                # create a new random key
                verkey = await self._session.handle.create_keypair(KeyAlg.ED25519)

            verkey = normalize_verkey(verkey)

            if not did:
                key_b58 = verkey.split(":")[0]
                did = bytes_to_b58(b58_to_bytes(key_b58)[:16])

            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if item:
                did_info = item.value_json
                if did_info.get("verkey") != verkey:
                    raise WalletDuplicateError("DID already present in wallet")
                if did_info.get("metadata") != metadata:
                    did_info["metadata"] = metadata
                    await self._session.handle.replace(
                        CATEGORY_DID, did, value_json=did_info, tags=item.tags
                    )
            else:
                await self._session.handle.insert(
                    CATEGORY_DID,
                    did,
                    value_json={"did": did, "verkey": verkey, "metadata": metadata},
                )

        except StoreError as err:
            raise WalletError("Error when creating local DID") from err

        return DIDInfo(did, verkey, metadata)

    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """
        Get list of defined local DIDs.

        Returns:
            A list of locally stored DIDs as `DIDInfo` instances

        """

        # FIXME this is potentially slow / memory intensive.
        # it also won't find a DID created in the current transaction before
        # that has been committed. Need to check use cases for this method

        ret = []
        for item in await self._session.handle.fetch_all(CATEGORY_DID):
            did_info = item.value_json
            ret.append(
                DIDInfo(
                    did=did_info["did"],
                    verkey=did_info["verkey"],
                    metadata=did_info.get("metadata"),
                )
            )
        return ret

    async def get_local_did(self, did: str) -> DIDInfo:
        """
        Find info for a local DID.

        Args:
            did: The DID for which to get info

        Returns:
            A `DIDInfo` instance representing the found DID

        Raises:
            WalletNotFoundError: If the DID is not found
            WalletError: If there is a libindy error

        """

        if not did:
            raise WalletNotFoundError("No identifier provided")
        try:
            did = await self._session.handle.fetch(CATEGORY_DID, did)
        except StoreError as err:
            raise WalletError("Error when fetching local DID") from err
        if not did:
            raise WalletNotFoundError("Unknown DID: {}".format(did))
        did_info = did.value_json
        return DIDInfo(
            did=did_info["did"],
            verkey=did_info["verkey"],
            metadata=did_info.get("metadata") or {},
        )

    async def get_local_did_for_verkey(self, verkey: str) -> DIDInfo:
        """
        Resolve a local DID from a verkey.

        Args:
            verkey: The verkey for which to get the local DID

        Returns:
            A `DIDInfo` instance representing the found DID

        Raises:
            WalletNotFoundError: If the verkey is not found

        """

        dids = await self.get_local_dids()
        for info in dids:
            if info.verkey == verkey:
                return info
        raise WalletNotFoundError("No DID defined for verkey: {}".format(verkey))

    async def replace_local_did_metadata(self, did: str, metadata: dict):
        """
        Replace metadata for a local DID.

        Args:
            did: The DID for which to replace metadata
            metadata: The new metadata

        """

        try:
            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if not item:
                raise WalletNotFoundError("Unknown DID: {}".format(did)) from None
            entry_val = item.value_json
            if entry_val["metadata"] != metadata:
                entry_val["metadata"] = metadata
                await self._session.handle.replace(
                    CATEGORY_DID, did, value_json=entry_val, tags=item.tags
                )
        except StoreError as err:
            raise WalletError("Error updating DID metadata") from err

    async def set_did_endpoint(
        self,
        did: str,
        endpoint: str,
        ledger: BaseLedger,
        endpoint_type: EndpointType = None,
    ):
        """
        Update the endpoint for a DID in the wallet, send to ledger if public or posted.

        Args:
            did: DID for which to set endpoint
            endpoint: the endpoint to set, None to clear
            ledger: the ledger to which to send endpoint update if
                DID is public or posted
            endpoint_type: the type of the endpoint/service. Only endpoint_type
                'endpoint' affects local wallet
        """
        did_info = await self.get_local_did(did)
        metadata = {**did_info.metadata}
        if not endpoint_type:
            endpoint_type = EndpointType.ENDPOINT
        if endpoint_type == EndpointType.ENDPOINT:
            metadata[endpoint_type.indy] = endpoint

        wallet_public_didinfo = await self.get_public_did()
        if (
            wallet_public_didinfo and wallet_public_didinfo.did == did
        ) or did_info.metadata.get("posted"):
            # if DID on ledger, set endpoint there first
            if not ledger:
                raise LedgerConfigError(
                    f"No ledger available but DID {did} is public: missing wallet-type?"
                )
            if not ledger.read_only:
                async with ledger:
                    await ledger.update_endpoint_for_did(did, endpoint, endpoint_type)

        await self.replace_local_did_metadata(did, metadata)

    async def rotate_did_keypair_start(self, did: str, next_seed: str = None) -> str:
        """
        Begin key rotation for DID that wallet owns: generate new keypair.

        Args:
            did: signing DID
            next_seed: incoming replacement seed (default random)

        Returns:
            The new verification key

        """
        # try:
        #     verkey = await indy.did.replace_keys_start(
        #         self.handle,
        #         did,
        #         json.dumps(
        #             {"seed": bytes_to_b64(validate_seed(next_seed))}
        #             if next_seed
        #             else {}
        #         ),
        #     )
        # except IndyError as x_indy:
        #     if x_indy.error_code == ErrorCode.WalletItemNotFound:
        #         raise WalletNotFoundError("Wallet owns no such DID: {}".format(did))
        #     raise IndyErrorHandler.wrap_error(
        #         x_indy, "Wallet {} error".format(self.name), WalletError
        #     ) from x_indy

        # return verkey

    async def rotate_did_keypair_apply(self, did: str) -> DIDInfo:
        """
        Apply temporary keypair as main for DID that wallet owns.

        Args:
            did: signing DID

        Returns:
            DIDInfo with new verification key and metadata for DID

        """
        # try:
        #     await indy.did.replace_keys_apply(self.handle, did)
        # except IndyError as x_indy:
        #     if x_indy.error_code == ErrorCode.WalletItemNotFound:
        #         raise WalletNotFoundError("Wallet owns no such DID: {}".format(did))
        #     raise IndyErrorHandler.wrap_error(
        #         x_indy, "Wallet {} error".format(self.name), WalletError
        #     ) from x_indy

    async def sign_message(self, message: bytes, from_verkey: str) -> bytes:
        """
        Sign a message using the private key associated with a given verkey.

        Args:
            message: Message bytes to sign
            from_verkey: The verkey to use to sign

        Returns:
            A signature

        Raises:
            WalletError: If the message is not provided
            WalletError: If the verkey is not provided
            WalletError: If a libindy error occurs

        """
        if not message:
            raise WalletError("Message not provided")
        if not from_verkey:
            raise WalletError("Verkey not provided")
        try:
            return await self._session.handle.sign_message(from_verkey, message)
        except StoreError as err:
            raise WalletError("Exception when signing message") from err

    async def verify_message(
        self, message: bytes, signature: bytes, from_verkey: str
    ) -> bool:
        """
        Verify a signature against the public key of the signer.

        Args:
            message: Message to verify
            signature: Signature to verify
            from_verkey: Verkey to use in verification

        Returns:
            True if verified, else False

        Raises:
            WalletError: If the verkey is not provided
            WalletError: If the signature is not provided
            WalletError: If the message is not provided
            WalletError: If a libindy error occurs

        """
        if not from_verkey:
            raise WalletError("Verkey not provided")
        if not signature:
            raise WalletError("Signature not provided")
        if not message:
            raise WalletError("Message not provided")

        try:
            return await verify_signature(from_verkey, message, signature)
        except StoreError as err:
            raise WalletError("Exception when verifying message signature") from err

    async def pack_message(
        self, message: str, to_verkeys: Sequence[str], from_verkey: str = None
    ) -> bytes:
        """
        Pack a message for one or more recipients.

        Args:
            message: The message to pack
            to_verkeys: List of verkeys for which to pack
            from_verkey: Sender verkey from which to pack

        Returns:
            The resulting packed message bytes

        Raises:
            WalletError: If no message is provided
            WalletError: If a libindy error occurs

        """
        if message is None:
            raise WalletError("Message not provided")
        try:
            return await self._session.handle.pack_message(
                to_verkeys, from_verkey, message
            )
        except StoreError as err:
            raise WalletError("Exception when packing message") from err

    async def unpack_message(self, enc_message: bytes) -> (str, str, str):
        """
        Unpack a message.

        Args:
            enc_message: The packed message bytes

        Returns:
            A tuple: (message, from_verkey, to_verkey)

        Raises:
            WalletError: If the message is not provided
            WalletError: If a libindy error occurs

        """
        if not enc_message:
            raise WalletError("Message not provided")
        try:
            (
                unpacked_json,
                recipient,
                sender,
            ) = await self._session.handle.unpack_message(enc_message)
        except StoreError as err:
            raise WalletError("Exception when unpacking message") from err
        return unpacked_json.decode("utf-8"), sender, recipient
