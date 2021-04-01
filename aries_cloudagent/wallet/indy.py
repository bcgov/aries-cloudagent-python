"""Indy implementation of BaseWallet interface."""

import json

from typing import Sequence, Tuple

import indy.anoncreds
import indy.did
import indy.crypto
import indy.wallet

from indy.error import IndyError, ErrorCode

from ..indy.sdk.error import IndyErrorHandler
from ..indy.sdk.wallet_setup import IndyOpenWallet
from ..ledger.base import BaseLedger
from ..ledger.endpoint_type import EndpointType
from ..ledger.error import LedgerConfigError

from .base import BaseWallet, KeyInfo, DIDInfo
from .crypto import validate_seed
from .error import WalletError, WalletDuplicateError, WalletNotFoundError
from .util import bytes_to_b64


class IndySdkWallet(BaseWallet):
    """Indy identity wallet implementation."""

    def __init__(self, opened: IndyOpenWallet):
        """Create a new IndySdkWallet instance."""
        self.opened = opened

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
        args = {}
        if seed:
            args["seed"] = bytes_to_b64(validate_seed(seed))
        try:
            verkey = await indy.crypto.create_key(self.opened.handle, json.dumps(args))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemAlreadyExists:
                raise WalletDuplicateError("Verification key already present in wallet")
            raise IndyErrorHandler.wrap_error(
                x_indy, "Wallet {} error".format(self.opened.name), WalletError
            ) from x_indy

        # must save metadata to allow identity check
        # otherwise get_key_metadata just returns WalletItemNotFound
        if metadata is None:
            metadata = {}
        await indy.crypto.set_key_metadata(
            self.opened.handle, verkey, json.dumps(metadata)
        )
        return KeyInfo(verkey, metadata)

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
        try:
            metadata = await indy.crypto.get_key_metadata(self.opened.handle, verkey)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                raise WalletNotFoundError("Unknown key: {}".format(verkey))
            else:
                raise IndyErrorHandler.wrap_error(
                    x_indy, "Wallet {} error".format(self.opened.name), WalletError
                ) from x_indy
        return KeyInfo(verkey, json.loads(metadata) if metadata else {})

    async def replace_signing_key_metadata(self, verkey: str, metadata: dict):
        """
        Replace the metadata associated with a signing keypair.

        Args:
            verkey: The verification key of the keypair
            metadata: The new metadata to store

        Raises:
            WalletNotFoundError: if no keypair is associated with the verification key

        """
        meta_json = json.dumps(metadata or {})
        await self.get_signing_key(verkey)  # throw exception if key is undefined
        await indy.crypto.set_key_metadata(self.opened.handle, verkey, meta_json)

    async def rotate_did_keypair_start(self, did: str, next_seed: str = None) -> str:
        """
        Begin key rotation for DID that wallet owns: generate new keypair.

        Args:
            did: signing DID
            next_seed: incoming replacement seed (default random)

        Returns:
            The new verification key

        """
        try:
            verkey = await indy.did.replace_keys_start(
                self.opened.handle,
                did,
                json.dumps(
                    {"seed": bytes_to_b64(validate_seed(next_seed))}
                    if next_seed
                    else {}
                ),
            )
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                raise WalletNotFoundError("Wallet owns no such DID: {}".format(did))
            raise IndyErrorHandler.wrap_error(
                x_indy, "Wallet {} error".format(self.opened.name), WalletError
            ) from x_indy

        return verkey

    async def rotate_did_keypair_apply(self, did: str) -> DIDInfo:
        """
        Apply temporary keypair as main for DID that wallet owns.

        Args:
            did: signing DID

        Returns:
            DIDInfo with new verification key and metadata for DID

        """
        try:
            await indy.did.replace_keys_apply(self.opened.handle, did)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                raise WalletNotFoundError("Wallet owns no such DID: {}".format(did))
            raise IndyErrorHandler.wrap_error(
                x_indy, "Wallet {} error".format(self.opened.name), WalletError
            ) from x_indy

    async def create_local_did(
        self,
        seed: str = None,
        did: str = None,
        method_name: str = None,
        metadata: dict = None,
    ) -> DIDInfo:
        """
        Create and store a new local DID.

        Args:
            seed: Optional seed to use for DID
            did: The DID to use
            method_name: The DID method to use
            metadata: Metadata to store with DID

        Returns:
            A `DIDInfo` instance representing the created DID

        Raises:
            WalletDuplicateError: If the DID already exists in the wallet
            WalletError: If there is a libindy error

        """
        cfg = {}
        if seed:
            cfg["seed"] = bytes_to_b64(validate_seed(seed))
        if did:
            cfg["did"] = did
        if method_name:
            # FIXME - use an application default method if not specified?
            cfg["method_name"] = method_name
        did_json = json.dumps(cfg)
        # crypto_type, cid - optional parameters skipped
        try:
            did, verkey = await indy.did.create_and_store_my_did(
                self.opened.handle, did_json
            )
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.DidAlreadyExistsError:
                raise WalletDuplicateError("DID already present in wallet")
            raise IndyErrorHandler.wrap_error(
                x_indy, "Wallet {} error".format(self.opened.name), WalletError
            ) from x_indy
        if metadata:
            await self.replace_local_did_metadata(did, metadata)
        else:
            metadata = {}
        return DIDInfo(did, verkey, metadata)

    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """
        Get list of defined local DIDs.

        Returns:
            A list of locally stored DIDs as `DIDInfo` instances

        """
        info_json = await indy.did.list_my_dids_with_meta(self.opened.handle)
        info = json.loads(info_json)
        ret = []
        for did in info:
            ret.append(
                DIDInfo(
                    did=did["did"],
                    verkey=did["verkey"],
                    metadata=json.loads(did["metadata"]) if did["metadata"] else {},
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

        try:
            info_json = await indy.did.get_my_did_with_meta(self.opened.handle, did)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                raise WalletNotFoundError("Unknown DID: {}".format(did))
            raise IndyErrorHandler.wrap_error(
                x_indy, "Wallet {} error".format(self.opened.name), WalletError
            ) from x_indy
        info = json.loads(info_json)
        return DIDInfo(
            did=info["did"],
            verkey=info["verkey"],
            metadata=json.loads(info["metadata"]) if info["metadata"] else {},
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
        meta_json = json.dumps(metadata or {})
        await self.get_local_did(did)  # throw exception if undefined
        try:
            await indy.did.set_did_metadata(self.opened.handle, did, meta_json)
        except IndyError as x_indy:
            raise IndyErrorHandler.wrap_error(
                x_indy, "Wallet {} error".format(self.opened.name), WalletError
            ) from x_indy

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
            result = await indy.crypto.crypto_sign(
                self.opened.handle, from_verkey, message
            )
        except IndyError:
            raise WalletError("Exception when signing message")
        return result

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
            result = await indy.crypto.crypto_verify(from_verkey, message, signature)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.CommonInvalidStructure:
                result = False
            else:
                raise IndyErrorHandler.wrap_error(
                    x_indy, "Wallet {} error".format(self.opened.name), WalletError
                ) from x_indy
        return result

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
            result = await indy.crypto.pack_message(
                self.opened.handle, message, to_verkeys, from_verkey
            )
        except IndyError as x_indy:
            raise IndyErrorHandler.wrap_error(
                x_indy, "Exception when packing message", WalletError
            ) from x_indy

        return result

    async def unpack_message(self, enc_message: bytes) -> Tuple[str, str, str]:
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
            unpacked_json = await indy.crypto.unpack_message(
                self.opened.handle, enc_message
            )
        except IndyError:
            raise WalletError("Exception when unpacking message")
        unpacked = json.loads(unpacked_json)
        message = unpacked["message"]
        to_verkey = unpacked.get("recipient_verkey", None)
        from_verkey = unpacked.get("sender_verkey", None)
        return message, from_verkey, to_verkey

    @classmethod
    async def generate_wallet_key(self, seed: str = None) -> str:
        """Generate a raw Indy wallet key."""
        return await indy.wallet.generate_wallet_key(seed)
