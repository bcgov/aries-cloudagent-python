"""Indy implementation of BaseWallet interface."""

import json

from typing import List, Sequence, Tuple, Union

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

from ..did.did_key import DIDKey
from .base import BaseWallet
from .crypto import (
    create_keypair,
    sign_message,
    validate_seed,
    verify_signed_message,
)
from .key_type import KeyType
from .did_method import DIDMethod
from .key_pair import KeyPairStorageManager
from ..storage.indy import IndySdkStorage
from ..storage.error import StorageDuplicateError, StorageNotFoundError
from .did_info import DIDInfo, KeyInfo
from .error import WalletError, WalletDuplicateError, WalletNotFoundError
from .util import b58_to_bytes, bytes_to_b58, bytes_to_b64


class IndySdkWallet(BaseWallet):
    """Indy identity wallet implementation."""

    def __init__(self, opened: IndyOpenWallet):
        """Create a new IndySdkWallet instance."""
        self.opened = opened

    def __did_info_from_indy_info(self, info):
        metadata = json.loads(info["metadata"]) if info["metadata"] else {}
        did: str = info["did"]
        verkey = info["verkey"]

        method = DIDMethod.KEY if did.startswith("did:key") else DIDMethod.SOV
        key_type = KeyType.ED25519

        if method == DIDMethod.KEY:
            did = DIDKey.from_public_key_b58(info["verkey"], key_type).did

        return DIDInfo(
            did=did, verkey=verkey, metadata=metadata, method=method, key_type=key_type
        )

    def __did_info_from_key_pair_info(self, info: dict):
        metadata = info["metadata"]
        verkey = info["verkey"]

        # this needs to change if other did methods are added
        method = DIDMethod.from_method(info["metadata"].get("method", "key"))
        key_type = KeyType.from_key_type(info["key_type"])

        if method == DIDMethod.KEY:
            did = DIDKey.from_public_key_b58(info["verkey"], key_type).did

        return DIDInfo(
            did=did, verkey=verkey, metadata=metadata, method=method, key_type=key_type
        )

    async def __create_indy_signing_key(
        self, key_type: KeyType, metadata: dict, seed: str = None
    ) -> str:
        if key_type != KeyType.ED25519:
            raise WalletError(f"Unsupported key type: {key_type.key_type}")

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

        await indy.crypto.set_key_metadata(
            self.opened.handle, verkey, json.dumps(metadata)
        )

        return verkey

    async def __create_keypair_signing_key(
        self, key_type: KeyType, metadata: dict, seed: str = None
    ) -> str:
        if key_type != KeyType.BLS12381G2:
            raise WalletError(f"Unsupported key type: {key_type.key_type}")

        public_key, secret_key = create_keypair(key_type, validate_seed(seed))
        verkey = bytes_to_b58(public_key)
        key_pair_mgr = KeyPairStorageManager(IndySdkStorage(self.opened))

        # Check if key already exists
        try:
            key_info = await self.__get_keypair_signing_key(verkey)
            if key_info:
                raise WalletDuplicateError("Verification key already present in wallet")
        except WalletNotFoundError:
            # If we can't find the key, it means it doesn't exist already
            # this is good
            pass

        await key_pair_mgr.store_key_pair(
            public_key=public_key,
            secret_key=secret_key,
            key_type=key_type,
            metadata=metadata,
        )

        return verkey

    async def create_signing_key(
        self, key_type: KeyType, seed: str = None, metadata: dict = None
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

        # must save metadata to allow identity check
        # otherwise get_key_metadata just returns WalletItemNotFound
        if metadata is None:
            metadata = {}

        # All ed25519 keys are handled by indy
        if key_type == KeyType.ED25519:
            verkey = await self.__create_indy_signing_key(key_type, metadata, seed)
        # All other (only bls12381g2 atm) are handled outside of indy
        else:
            verkey = await self.__create_keypair_signing_key(key_type, metadata, seed)

        return KeyInfo(verkey=verkey, metadata=metadata, key_type=key_type)

    async def __get_indy_signing_key(self, verkey: str) -> KeyInfo:
        try:
            metadata = await indy.crypto.get_key_metadata(self.opened.handle, verkey)

            return KeyInfo(
                verkey=verkey,
                metadata=json.loads(metadata) if metadata else {},
                key_type=KeyType.ED25519,
            )
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                raise WalletNotFoundError(f"Unknown key: {verkey}")
            # # If we resolve a key that is not 32 bytes we get CommonInvalidStructure
            # elif x_indy.error_code == ErrorCode.CommonInvalidStructure:
            #     raise WalletNotFoundError(f"Unknown key: {verkey}")
            else:
                raise IndyErrorHandler.wrap_error(
                    x_indy, "Wallet {} error".format(self.opened.name), WalletError
                ) from x_indy

    async def __get_keypair_signing_key(self, verkey: str) -> KeyInfo:
        try:
            key_pair_mgr = KeyPairStorageManager(IndySdkStorage(self.opened))
            key_pair = await key_pair_mgr.get_key_pair(verkey)
            return KeyInfo(
                verkey=verkey,
                metadata=key_pair["metadata"],
                key_type=KeyType.from_key_type(key_pair["key_type"]),
            )
        except (StorageNotFoundError):
            raise WalletNotFoundError(f"Unknown key: {verkey}")
        except (StorageDuplicateError):
            raise WalletDuplicateError(f"Multiple keys exist for verkey: {verkey}")

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
            raise WalletError("Missing required input parameter: verkey")

        # Only try to load indy signing key if the verkey is 32 bytes
        # this may change if indy is going to support verkeys of different byte length
        if len(b58_to_bytes(verkey)) == 32:
            try:
                return await self.__get_indy_signing_key(verkey)
            except WalletNotFoundError:
                return await self.__get_keypair_signing_key(verkey)
        else:
            return await self.__get_keypair_signing_key(verkey)

    async def replace_signing_key_metadata(self, verkey: str, metadata: dict):
        """
        Replace the metadata associated with a signing keypair.

        Args:
            verkey: The verification key of the keypair
            metadata: The new metadata to store

        Raises:
            WalletNotFoundError: if no keypair is associated with the verification key

        """
        metadata = metadata or {}

        # throw exception if key is undefined
        key_info = await self.get_signing_key(verkey)

        # All ed25519 keys are handled by indy
        if key_info.key_type == KeyType.ED25519:
            await indy.crypto.set_key_metadata(
                self.opened.handle, verkey, json.dumps(metadata)
            )
        # All other (only bls12381g2 atm) are handled outside of indy
        else:
            key_pair_mgr = KeyPairStorageManager(IndySdkStorage(self.opened))
            await key_pair_mgr.update_key_pair_metadata(
                verkey=key_info.verkey, metadata=metadata
            )

    async def rotate_did_keypair_start(self, did: str, next_seed: str = None) -> str:
        """
        Begin key rotation for DID that wallet owns: generate new keypair.

        Args:
            did: signing DID
            next_seed: incoming replacement seed (default random)

        Returns:
            The new verification key

        """
        # Check if DID can rotate keys
        did_method = DIDMethod.from_did(did)
        if not did_method.supports_rotation:
            raise WalletError(
                f"DID method '{did_method.method_name}' does not support key rotation."
            )

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

    async def __create_indy_local_did(
        self,
        method: DIDMethod,
        key_type: KeyType,
        metadata: dict = None,
        seed: str = None,
        *,
        did: str = None,
    ) -> DIDInfo:
        if method not in [DIDMethod.SOV, DIDMethod.KEY]:
            raise WalletError(
                f"Unsupported DID method for indy storage: {method.method_name}"
            )
        if key_type != KeyType.ED25519:
            raise WalletError(
                f"Unsupported key type for indy storage: {key_type.key_type}"
            )

        cfg = {}
        if seed:
            cfg["seed"] = bytes_to_b64(validate_seed(seed))
        if did:
            cfg["did"] = did
        # Create fully qualified did. This helps with determining the
        # did method when retrieving
        if method != DIDMethod.SOV:
            cfg["method_name"] = method.method_name
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

        # did key uses different format
        if method == DIDMethod.KEY:
            did = DIDKey.from_public_key_b58(verkey, key_type).did

        await self.replace_local_did_metadata(did, metadata or {})

        return DIDInfo(
            did=did,
            verkey=verkey,
            metadata=metadata or {},
            method=method,
            key_type=key_type,
        )

    async def __create_keypair_local_did(
        self,
        method: DIDMethod,
        key_type: KeyType,
        metadata: dict = None,
        seed: str = None,
    ) -> DIDInfo:
        if method != DIDMethod.KEY:
            raise WalletError(
                f"Unsupported DID method for keypair storage: {method.method_name}"
            )
        if key_type != KeyType.BLS12381G2:
            raise WalletError(
                f"Unsupported key type for keypair storage: {key_type.key_type}"
            )

        public_key, secret_key = create_keypair(key_type, validate_seed(seed))
        key_pair_mgr = KeyPairStorageManager(IndySdkStorage(self.opened))
        # should change if other did methods are supported
        did_key = DIDKey.from_public_key(public_key, key_type)

        if not metadata:
            metadata = {}
        metadata["method"] = method.method_name

        await key_pair_mgr.store_key_pair(
            public_key=public_key,
            secret_key=secret_key,
            key_type=key_type,
            metadata=metadata,
            tags={"method": method.method_name},
        )

        return DIDInfo(
            did=did_key.did,
            verkey=did_key.public_key_b58,
            metadata=metadata,
            method=method,
            key_type=key_type,
        )

    async def create_local_did(
        self,
        method: DIDMethod,
        key_type: KeyType,
        seed: str = None,
        did: str = None,
        metadata: dict = None,
    ) -> DIDInfo:
        """
        Create and store a new local DID.

        Args:
            method: The method to use for the DID
            key_type: The key type to use for the DID
            seed: Optional seed to use for DID
            did: The DID to use
            metadata: Metadata to store with DID

        Returns:
            A `DIDInfo` instance representing the created DID

        Raises:
            WalletDuplicateError: If the DID already exists in the wallet
            WalletError: If there is a libindy error

        """

        # validate key_type
        if not method.supports_key_type(key_type):
            raise WalletError(
                f"Invalid key type {key_type.key_type}"
                f" for DID method {method.method_name}"
            )

        if method == DIDMethod.KEY and did:
            raise WalletError("Not allowed to set DID for DID method 'key'")

        # All ed25519 keys are handled by indy
        if key_type == KeyType.ED25519:
            return await self.__create_indy_local_did(
                method, key_type, metadata, seed, did=did
            )
        # All other (only bls12381g2 atm) are handled outside of indy
        else:
            return await self.__create_keypair_local_did(
                method, key_type, metadata, seed
            )

    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """
        Get list of defined local DIDs.

        Returns:
            A list of locally stored DIDs as `DIDInfo` instances

        """
        # retrieve indy dids
        info_json = await indy.did.list_my_dids_with_meta(self.opened.handle)
        info = json.loads(info_json)
        ret = []
        for did in info:
            ret.append(self.__did_info_from_indy_info(did))

        # retrieve key pairs with method set to key
        # this needs to change if more did methods are added
        key_pair_mgr = KeyPairStorageManager(IndySdkStorage(self.opened))
        key_pairs = await key_pair_mgr.find_key_pairs(
            tag_query={"method": DIDMethod.KEY.method_name}
        )
        for key_pair in key_pairs:
            ret.append(self.__did_info_from_key_pair_info(key_pair))

        return ret

    async def __get_indy_local_did(
        self, method: DIDMethod, key_type: KeyType, did: str
    ) -> DIDInfo:
        if method not in [DIDMethod.SOV, DIDMethod.KEY]:
            raise WalletError(
                f"Unsupported DID method for indy storage: {method.method_name}"
            )
        if key_type != KeyType.ED25519:
            raise WalletError(
                f"Unsupported DID type for indy storage: {key_type.key_type}"
            )

        # key type is always ed25519, method not always key
        if method == DIDMethod.KEY and key_type == KeyType.ED25519:
            did_key = DIDKey.from_did(did)

            # Ed25519 did:keys are masked indy dids so transform to indy
            # did with did:key prefix.
            did = "did:key:" + bytes_to_b58(did_key.public_key[:16])
        try:
            info_json = await indy.did.get_my_did_with_meta(self.opened.handle, did)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                raise WalletNotFoundError("Unknown DID: {}".format(did))
            raise IndyErrorHandler.wrap_error(
                x_indy, "Wallet {} error".format(self.opened.name), WalletError
            ) from x_indy
        info = json.loads(info_json)
        return self.__did_info_from_indy_info(info)

    async def __get_keypair_local_did(
        self, method: DIDMethod, key_type: KeyType, did: str
    ):
        if method != DIDMethod.KEY:
            raise WalletError(
                f"Unsupported DID method for keypair storage: {method.method_name}"
            )
        if key_type != KeyType.BLS12381G2:
            raise WalletError(
                f"Unsupported DID type for keypair storage: {key_type.key_type}"
            )

        # method is always did:key
        did_key = DIDKey.from_did(did)

        key_pair_mgr = KeyPairStorageManager(IndySdkStorage(self.opened))
        key_pair = await key_pair_mgr.get_key_pair(verkey=did_key.public_key_b58)
        return self.__did_info_from_key_pair_info(key_pair)

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
        method = DIDMethod.from_did(did)
        key_type = KeyType.ED25519

        # If did key, the key type can differ
        if method == DIDMethod.KEY:
            did_key = DIDKey.from_did(did)
            key_type = did_key.key_type

        if key_type == KeyType.ED25519:
            return await self.__get_indy_local_did(method, key_type, did)
        else:
            return await self.__get_keypair_local_did(method, key_type, did)

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
        if not metadata:
            metadata = {}
        did_info = await self.get_local_did(did)  # throw exception if undefined

        # ed25519 keys are handled by indy
        if did_info.key_type == KeyType.ED25519:
            try:
                await indy.did.set_did_metadata(
                    self.opened.handle, did, json.dumps(metadata)
                )
            except IndyError as x_indy:
                raise IndyErrorHandler.wrap_error(
                    x_indy, "Wallet {} error".format(self.opened.name), WalletError
                ) from x_indy
        # all other keys are handled by key pair
        else:
            key_pair_mgr = KeyPairStorageManager(IndySdkStorage(self.opened))
            await key_pair_mgr.update_key_pair_metadata(
                verkey=did_info.verkey, metadata=metadata
            )

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
        if did_info.method != DIDMethod.SOV:
            raise WalletError("Setting DID endpoint is only allowed for did:sov DIDs")

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
            key_info = await self.get_signing_key(from_verkey)
        except WalletNotFoundError:
            key_info = await self.get_local_did_for_verkey(from_verkey)

        # ed25519 keys are handled by indy
        if key_info.key_type == KeyType.ED25519:
            try:
                result = await indy.crypto.crypto_sign(
                    self.opened.handle, from_verkey, message
                )
            except IndyError:
                raise WalletError("Exception when signing message")
        # other keys are handled outside of indy
        else:
            key_pair_mgr = KeyPairStorageManager(IndySdkStorage(self.opened))
            key_pair = await key_pair_mgr.get_key_pair(verkey=key_info.verkey)
            result = sign_message(
                message=message,
                secret=b58_to_bytes(key_pair["secret_key"]),
                key_type=key_info.key_type,
            )

        return result

    async def verify_message(
        self,
        message: Union[List[bytes], bytes],
        signature: bytes,
        from_verkey: str,
        key_type: KeyType,
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

        # ed25519 keys are handled by indy
        if key_type == KeyType.ED25519:
            try:
                result = await indy.crypto.crypto_verify(
                    from_verkey, message, signature
                )
            except IndyError as x_indy:
                if x_indy.error_code == ErrorCode.CommonInvalidStructure:
                    result = False
                else:
                    raise IndyErrorHandler.wrap_error(
                        x_indy, "Wallet {} error".format(self.opened.name), WalletError
                    ) from x_indy
            return result
        # all other keys (only bls12381g2 atm) are handled outside of indy
        else:
            return verify_signed_message(
                message=message,
                signature=signature,
                verkey=b58_to_bytes(from_verkey),
                key_type=key_type,
            )

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
