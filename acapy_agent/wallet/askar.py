"""Aries-Askar implementation of BaseWallet interface."""

import asyncio
import json
import logging
from typing import List, Optional, Sequence, Tuple, Union, cast

from aries_askar import AskarError, AskarErrorCode, Entry, Key, KeyAlg, SeedMethod

from ..askar.didcomm.v1 import pack_message, unpack_message
from ..askar.profile import AskarProfileSession
from ..ledger.base import BaseLedger
from ..ledger.endpoint_type import EndpointType
from ..ledger.error import LedgerConfigError
from ..storage.askar import AskarStorage
from ..storage.base import StorageDuplicateError, StorageNotFoundError, StorageRecord
from .base import BaseWallet, DIDInfo, KeyInfo
from .crypto import sign_message, validate_seed, verify_signed_message
from .did_info import INVITATION_REUSE_KEY
from .did_method import INDY, SOV, DIDMethod, DIDMethods
from .did_parameters_validation import DIDParametersValidation
from .error import WalletDuplicateError, WalletError, WalletNotFoundError
from .key_type import BLS12381G2, ED25519, P256, X25519, KeyType, KeyTypes
from .util import b58_to_bytes, bytes_to_b58

CATEGORY_DID = "did"
CATEGORY_CONFIG = "config"
RECORD_NAME_PUBLIC_DID = "default_public_did"

LOGGER = logging.getLogger(__name__)


class AskarWallet(BaseWallet):
    """Aries-Askar wallet implementation."""

    def __init__(self, session: AskarProfileSession):
        """Initialize a new `AskarWallet` instance.

        Args:
            session: The Askar profile session instance to use
        """
        self._session = session

    @property
    def session(self) -> AskarProfileSession:
        """Accessor for Askar profile session instance."""
        return self._session

    async def create_signing_key(
        self,
        key_type: KeyType,
        seed: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> KeyInfo:
        """Create a new public/private signing keypair.

        Args:
            key_type: Key type to create
            seed: Seed for key
            metadata: Optional metadata to store with the keypair

        Returns:
            A `KeyInfo` representing the new record

        Raises:
            WalletDuplicateError: If the resulting verkey already exists in the wallet
            WalletError: If there is another backend error

        """
        return await self.create_key(key_type, seed, metadata)

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
        if metadata is None:
            metadata = {}

        tags = {"kid": kid} if kid else None

        try:
            keypair = _create_keypair(key_type, seed)
            verkey = bytes_to_b58(keypair.get_public_bytes())
            await self._session.handle.insert_key(
                verkey,
                keypair,
                metadata=json.dumps(metadata),
                tags=tags,
            )
        except AskarError as err:
            if err.code == AskarErrorCode.DUPLICATE:
                raise WalletDuplicateError(
                    "Verification key already present in wallet"
                ) from None
            raise WalletError("Error creating signing key") from err
        return KeyInfo(verkey=verkey, metadata=metadata, key_type=key_type, kid=kid)

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
        key_entry = await self._session.handle.fetch_key(name=verkey, for_update=True)
        if not key_entry:
            raise WalletNotFoundError(f"No key entry found for verkey {verkey}")

        key = cast(Key, key_entry.key)
        metadata = cast(dict, key_entry.metadata)
        key_types = self.session.inject(KeyTypes)
        key_type = key_types.from_key_type(key.algorithm.value)
        if not key_type:
            raise WalletError(f"Unknown key type {key.algorithm.value}")

        await self._session.handle.update_key(name=verkey, tags={"kid": kid})
        return KeyInfo(verkey=verkey, metadata=metadata, key_type=key_type, kid=kid)

    async def get_key_by_kid(self, kid: str) -> KeyInfo:
        """Fetch a key by looking up its kid.

        Args:
            kid: the key identifier

        Returns:
            The key identified by kid

        """
        key_entries = await self._session.handle.fetch_all_keys(
            tag_filter={"kid": kid}, limit=2
        )
        if len(key_entries) > 1:
            raise WalletDuplicateError(f"More than one key found by kid {kid}")

        entry = key_entries[0]
        key = cast(Key, entry.key)
        verkey = bytes_to_b58(key.get_public_bytes())
        metadata = cast(dict, entry.metadata)
        key_types = self.session.inject(KeyTypes)
        key_type = key_types.from_key_type(key.algorithm.value)
        if not key_type:
            raise WalletError(f"Unknown key type {key.algorithm.value}")

        return KeyInfo(verkey=verkey, metadata=metadata, key_type=key_type, kid=kid)

    async def get_signing_key(self, verkey: str) -> KeyInfo:
        """Fetch info for a signing keypair.

        Args:
            verkey: The verification key of the keypair

        Returns:
            A `KeyInfo` representing the keypair

        Raises:
            WalletNotFoundError: If no keypair is associated with the verification key
            WalletError: If there is another backend error

        """

        if not verkey:
            raise WalletNotFoundError("No key identifier provided")
        key_entry = await self._session.handle.fetch_key(verkey)
        if not key_entry:
            raise WalletNotFoundError("Unknown key: {}".format(verkey))
        metadata = json.loads(key_entry.metadata or "{}")

        try:
            kid = key_entry.tags.get("kid")
        except Exception:
            kid = None

        key = cast(Key, key_entry.key)
        key_types = self.session.inject(KeyTypes)
        key_type = key_types.from_key_type(key.algorithm.value)
        if not key_type:
            raise WalletError(f"Unknown key type {key.algorithm.value}")
        return KeyInfo(verkey=verkey, metadata=metadata, key_type=key_type, kid=kid)

    async def replace_signing_key_metadata(self, verkey: str, metadata: dict):
        """Replace the metadata associated with a signing keypair.

        Args:
            verkey: The verification key of the keypair
            metadata: The new metadata to store

        Raises:
            WalletNotFoundError: if no keypair is associated with the verification key

        """

        # FIXME caller should always create a transaction first

        if not verkey:
            raise WalletNotFoundError("No key identifier provided")

        key = await self._session.handle.fetch_key(verkey, for_update=True)
        if not key:
            raise WalletNotFoundError("Keypair not found")
        await self._session.handle.update_key(
            verkey, metadata=json.dumps(metadata or {}), tags=key.tags
        )

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
            A `DIDInfo` instance representing the created DID

        Raises:
            WalletDuplicateError: If the DID already exists in the wallet
            WalletError: If there is another backend error

        """
        did_validation = DIDParametersValidation(self._session.context.inject(DIDMethods))
        did_validation.validate_key_type(method, key_type)

        if not metadata:
            metadata = {}

        try:
            keypair = _create_keypair(key_type, seed)
            verkey_bytes = keypair.get_public_bytes()
            verkey = bytes_to_b58(verkey_bytes)

            did = did_validation.validate_or_derive_did(
                method, key_type, verkey_bytes, did
            )

            try:
                await self._session.handle.insert_key(
                    verkey, keypair, metadata=json.dumps(metadata)
                )
            except AskarError as err:
                if err.code == AskarErrorCode.DUPLICATE:
                    # update metadata?
                    pass
                else:
                    raise WalletError("Error inserting key") from err

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
                value_json = {
                    "did": did,
                    "method": method.method_name,
                    "verkey": verkey,
                    "verkey_type": key_type.key_type,
                    "metadata": metadata,
                }
                tags = {
                    "method": method.method_name,
                    "verkey": verkey,
                    "verkey_type": key_type.key_type,
                }
                if INVITATION_REUSE_KEY in metadata:
                    tags[INVITATION_REUSE_KEY] = "true"
                await self._session.handle.insert(
                    CATEGORY_DID,
                    did,
                    value_json=value_json,
                    tags=tags,
                )

        except AskarError as err:
            raise WalletError("Error when creating local DID") from err

        return DIDInfo(
            did=did, verkey=verkey, metadata=metadata, method=method, key_type=key_type
        )

    async def store_did(self, did_info: DIDInfo) -> DIDInfo:
        """Store a DID in the wallet.

        This enables components external to the wallet to define how a DID
        is created and then store it in the wallet for later use.

        Args:
            did_info: The DID to store

        Returns:
            The stored `DIDInfo`
        """
        try:
            item = await self._session.handle.fetch(
                CATEGORY_DID, did_info.did, for_update=True
            )
            if item:
                raise WalletDuplicateError("DID already present in wallet")
            else:
                value_json = {
                    "did": did_info.did,
                    "method": did_info.method.method_name,
                    "verkey": did_info.verkey,
                    "verkey_type": did_info.key_type.key_type,
                    "metadata": did_info.metadata,
                }
                tags = {
                    "method": did_info.method.method_name,
                    "verkey": did_info.verkey,
                    "verkey_type": did_info.key_type.key_type,
                }
                if INVITATION_REUSE_KEY in did_info.metadata:
                    tags[INVITATION_REUSE_KEY] = "true"
                await self._session.handle.insert(
                    CATEGORY_DID,
                    did_info.did,
                    value_json=value_json,
                    tags=tags,
                )
        except AskarError as err:
            raise WalletError("Error when storing DID") from err

        return did_info

    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """Get list of defined local DIDs.

        Returns:
            A list of locally stored DIDs as `DIDInfo` instances

        """

        ret = []
        for item in await self._session.handle.fetch_all(CATEGORY_DID):
            ret.append(self._load_did_entry(item))
        return ret

    async def get_local_did(self, did: str) -> DIDInfo:
        """Find info for a local DID.

        Args:
            did: The DID for which to get info

        Returns:
            A `DIDInfo` instance representing the found DID

        Raises:
            WalletNotFoundError: If the DID is not found
            WalletError: If there is another backend error

        """

        if not did:
            raise WalletNotFoundError("No identifier provided")
        try:
            did_entry = await self._session.handle.fetch(CATEGORY_DID, did)
        except AskarError as err:
            raise WalletError("Error when fetching local DID") from err
        if not did_entry:
            raise WalletNotFoundError("Unknown DID: {}".format(did))
        return self._load_did_entry(did_entry)

    async def get_local_did_for_verkey(self, verkey: str) -> DIDInfo:
        """Resolve a local DID from a verkey.

        Args:
            verkey: The verkey for which to get the local DID

        Returns:
            A `DIDInfo` instance representing the found DID

        Raises:
            WalletNotFoundError: If the verkey is not found

        """

        try:
            dids = await self._session.handle.fetch_all(CATEGORY_DID, {"verkey": verkey})
        except AskarError as err:
            raise WalletError("Error when fetching local DID for verkey") from err
        if dids:
            ret_did = dids[0]
            ret_did_info = ret_did.value_json
            if len(dids) > 1 and ret_did_info["did"].startswith("did:peer:4"):
                # if it is a peer:did:4 make sure we are using the short version
                other_did = dids[1]  # assume only 2
                other_did_info = other_did.value_json
                if len(other_did_info["did"]) < len(ret_did_info["did"]):
                    ret_did = other_did
                    ret_did_info = other_did.value_json
            return self._load_did_entry(ret_did)
        raise WalletNotFoundError("No DID defined for verkey: {}".format(verkey))

    async def replace_local_did_metadata(self, did: str, metadata: dict):
        """Replace metadata for a local DID.

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
        except AskarError as err:
            raise WalletError("Error updating DID metadata") from err

    async def get_public_did(self) -> DIDInfo | None:
        """Retrieve the public DID.

        Returns:
            The currently public `DIDInfo`, if any

        """
        public_did = None
        public_info = None
        public_item = None
        storage = AskarStorage(self._session)
        try:
            public_item = await storage.get_record(
                CATEGORY_CONFIG, RECORD_NAME_PUBLIC_DID
            )
        except StorageNotFoundError:
            # populate public DID record
            # this should only happen once, for an upgraded wallet
            # the 'public' metadata flag is no longer used
            dids = await self.get_local_dids()
            for info in dids:
                if info.metadata.get("public"):
                    public_did = info.did
                    public_info = info
                    break
            try:
                # even if public is not set, store a record
                # to avoid repeated queries
                await storage.add_record(
                    StorageRecord(
                        type=CATEGORY_CONFIG,
                        id=RECORD_NAME_PUBLIC_DID,
                        value=json.dumps({"did": public_did}),
                    )
                )
            except StorageDuplicateError:
                # another process stored the record first
                public_item = await storage.get_record(
                    CATEGORY_CONFIG, RECORD_NAME_PUBLIC_DID
                )
        if public_item:
            public_did = json.loads(public_item.value)["did"]
            if public_did:
                try:
                    public_info = await self.get_local_did(public_did)
                except WalletNotFoundError:
                    pass

        return public_info

    async def set_public_did(self, did: Union[str, DIDInfo]) -> DIDInfo:
        """Assign the public DID.

        Returns:
            The updated `DIDInfo`

        """

        if isinstance(did, str):
            try:
                item = await self._session.handle.fetch(
                    CATEGORY_DID, did, for_update=True
                )
            except AskarError as err:
                raise WalletError("Error when fetching local DID") from err
            if not item:
                raise WalletNotFoundError("Unknown DID: {}".format(did))
            info = self._load_did_entry(item)
        else:
            info = did
            item = None

        public = await self.get_public_did()
        if not public or public.did != info.did:
            storage = AskarStorage(self._session)
            if not info.metadata.get("posted"):
                metadata = {**info.metadata, "posted": True}
                if item:
                    entry_val = item.value_json
                    entry_val["metadata"] = metadata
                    await self._session.handle.replace(
                        CATEGORY_DID, did, value_json=entry_val, tags=item.tags
                    )
                else:
                    await self.replace_local_did_metadata(info.did, metadata)
                info = info._replace(
                    metadata=metadata,
                )
            await storage.update_record(
                StorageRecord(
                    type=CATEGORY_CONFIG,
                    id=RECORD_NAME_PUBLIC_DID,
                    value="{}",
                ),
                value=json.dumps({"did": info.did}),
                tags=None,
            )
            public = info

        return public

    async def set_did_endpoint(
        self,
        did: str,
        endpoint: str,
        ledger: BaseLedger,
        endpoint_type: Optional[EndpointType] = None,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
        routing_keys: Optional[List[str]] = None,
    ):
        """Update the endpoint for a DID in the wallet, send to ledger if posted.

        Args:
            did (str): The DID for which to set the endpoint.
            endpoint (str): The endpoint to set. Use None to clear the endpoint.
            ledger (BaseLedger): The ledger to which to send the endpoint update if the
                DID is public or posted.
            endpoint_type (EndpointType, optional): The type of the endpoint/service.
                Only endpoint_type 'endpoint' affects the local wallet. Defaults to None.
            write_ledger (bool, optional): Whether to write the endpoint update to the
                ledger. Defaults to True.
            endorser_did (str, optional): The DID of the endorser. Defaults to None.
            routing_keys (List[str], optional): The routing keys to be used.
                Defaults to None.

        Raises:
            WalletError: If the DID is not of type 'did:sov'.
            LedgerConfigError: If no ledger is available but the DID is public.

        Returns:
            dict: The attribute definition if write_ledger is False, otherwise None.

        """
        did_info = await self.get_local_did(did)
        if did_info.method not in (SOV, INDY):
            raise WalletError(
                "Setting DID endpoint is only allowed for did:sov or did:indy DIDs"
            )
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
                    attrib_def = await ledger.update_endpoint_for_did(
                        did,
                        endpoint,
                        endpoint_type,
                        write_ledger=write_ledger,
                        endorser_did=endorser_did,
                        routing_keys=routing_keys,
                    )
                    if not write_ledger:
                        return attrib_def

        await self.replace_local_did_metadata(did, metadata)

    async def rotate_did_keypair_start(
        self, did: str, next_seed: Optional[str] = None
    ) -> str:
        """Begin key rotation for DID that wallet owns: generate new keypair.

        Args:
            did: signing DID
            next_seed: incoming replacement seed (default random)

        Returns:
            The new verification key

        """
        # Check if DID can rotate keys
        did_methods = self._session.inject(DIDMethods)
        did_method: DIDMethod = did_methods.from_did(did)
        if not did_method.supports_rotation:
            raise WalletError(
                f"DID method '{did_method.method_name}' does not support key rotation."
            )

        # create a new key to be rotated to (only did:sov/ED25519 supported for now)
        keypair = _create_keypair(ED25519, next_seed)
        verkey = bytes_to_b58(keypair.get_public_bytes())
        try:
            await self._session.handle.insert_key(
                verkey,
                keypair,
            )
        except AskarError as err:
            if err.code == AskarErrorCode.DUPLICATE:
                pass
            else:
                raise WalletError(
                    "Error when creating new keypair for local DID"
                ) from err

        try:
            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if not item:
                raise WalletNotFoundError("Unknown DID: {}".format(did)) from None
            entry_val = item.value_json
            metadata = entry_val.get("metadata", {})
            metadata["next_verkey"] = verkey
            entry_val["metadata"] = metadata
            await self._session.handle.replace(
                CATEGORY_DID, did, value_json=entry_val, tags=item.tags
            )
        except AskarError as err:
            raise WalletError("Error updating DID metadata") from err

        return verkey

    async def rotate_did_keypair_apply(self, did: str) -> DIDInfo:
        """Apply temporary keypair as main for DID that wallet owns.

        Args:
            did: signing DID

        Returns:
            DIDInfo with new verification key and metadata for DID

        """
        try:
            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if not item:
                raise WalletNotFoundError("Unknown DID: {}".format(did)) from None
            entry_val = item.value_json
            metadata = entry_val.get("metadata", {})
            next_verkey = metadata.get("next_verkey")
            if not next_verkey:
                raise WalletError("Cannot rotate DID key: no next key established")
            del metadata["next_verkey"]
            entry_val["verkey"] = next_verkey
            item.tags["verkey"] = next_verkey
            await self._session.handle.replace(
                CATEGORY_DID, did, value_json=entry_val, tags=item.tags
            )
        except AskarError as err:
            raise WalletError("Error updating DID metadata") from err

    async def sign_message(
        self, message: Union[List[bytes], bytes], from_verkey: str
    ) -> bytes:
        """Sign message(s) using the private key associated with a given verkey.

        Args:
            message: The message(s) to sign
            from_verkey: Sign using the private key related to this verkey

        Returns:
            A signature

        Raises:
            WalletError: If the message is not provided
            WalletError: If the verkey is not provided
            WalletError: If another backend error occurs

        """
        if not message:
            raise WalletError("Message not provided")
        if not from_verkey:
            raise WalletError("Verkey not provided")
        try:
            keypair = await self._session.handle.fetch_key(from_verkey)
            if not keypair:
                raise WalletNotFoundError("Missing key for sign operation")
            key = keypair.key
            if key.algorithm == KeyAlg.BLS12_381_G2:
                # for now - must extract the key and use sign_message
                return sign_message(
                    message=message,
                    secret=key.get_secret_bytes(),
                    key_type=BLS12381G2,
                )

            else:
                return key.sign_message(message)
        except AskarError as err:
            raise WalletError("Exception when signing message") from err

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

        Raises:
            WalletError: If the verkey is not provided
            WalletError: If the signature is not provided
            WalletError: If the message is not provided
            WalletError: If another backend error occurs

        """
        if not from_verkey:
            raise WalletError("Verkey not provided")
        if not signature:
            raise WalletError("Signature not provided")
        if not message:
            raise WalletError("Message not provided")

        verkey = b58_to_bytes(from_verkey)

        if key_type == ED25519:
            try:
                pk = Key.from_public_bytes(KeyAlg.ED25519, verkey)
                return pk.verify_signature(message, signature)
            except AskarError as err:
                raise WalletError("Exception when verifying message signature") from err
        elif key_type == P256:
            try:
                pk = Key.from_public_bytes(KeyAlg.P256, verkey)
                return pk.verify_signature(message, signature)
            except AskarError as err:
                raise WalletError("Exception when verifying message signature") from err

        # other key types are currently verified outside of Askar
        return verify_signed_message(
            message=message,
            signature=signature,
            verkey=verkey,
            key_type=key_type,
        )

    async def pack_message(
        self, message: str, to_verkeys: Sequence[str], from_verkey: Optional[str] = None
    ) -> bytes:
        """Pack a message for one or more recipients.

        Args:
            message: The message to pack
            to_verkeys: List of verkeys for which to pack
            from_verkey: Sender verkey from which to pack

        Returns:
            The resulting packed message bytes

        Raises:
            WalletError: If no message is provided
            WalletError: If another backend error occurs

        """
        if message is None:
            raise WalletError("Message not provided")
        try:
            if from_verkey:
                from_key_entry = await self._session.handle.fetch_key(from_verkey)
                if not from_key_entry:
                    raise WalletNotFoundError("Missing key for pack operation")
                from_key = from_key_entry.key
            else:
                from_key = None
            return await asyncio.get_event_loop().run_in_executor(
                None, pack_message, to_verkeys, from_key, message
            )
        except AskarError as err:
            raise WalletError("Exception when packing message") from err

    async def unpack_message(self, enc_message: bytes) -> Tuple[str, str, str]:
        """Unpack a message.

        Args:
            enc_message: The packed message bytes

        Returns:
            A tuple: (message, from_verkey, to_verkey)

        Raises:
            WalletError: If the message is not provided
            WalletError: If another backend error occurs

        """
        if not enc_message:
            raise WalletError("Message not provided")
        try:
            (
                unpacked_json,
                recipient,
                sender,
            ) = await unpack_message(self._session.handle, enc_message)
        except AskarError as err:
            raise WalletError("Exception when unpacking message") from err
        return unpacked_json.decode("utf-8"), sender, recipient

    def _load_did_entry(self, entry: Entry) -> DIDInfo:
        """Convert a DID record into the expected DIDInfo format."""
        did_info = entry.value_json
        did_methods: DIDMethods = self._session.inject(DIDMethods)
        key_types: KeyTypes = self._session.inject(KeyTypes)
        return DIDInfo(
            did=did_info["did"],
            verkey=did_info["verkey"],
            metadata=did_info.get("metadata"),
            method=did_methods.from_method(did_info.get("method", "sov")) or SOV,
            key_type=key_types.from_key_type(did_info.get("verkey_type", "ed25519"))
            or ED25519,
        )


def _create_keypair(key_type: KeyType, seed: Union[str, bytes, None] = None) -> Key:
    """Instantiate a new keypair with an optional seed value."""
    if key_type == ED25519:
        alg = KeyAlg.ED25519
        method = None
    # elif key_type == BLS12381G1:
    #     alg = KeyAlg.BLS12_381_G1
    elif key_type == X25519:
        alg = KeyAlg.X25519
        method = None
    elif key_type == P256:
        alg = KeyAlg.P256
    elif key_type == BLS12381G2:
        alg = KeyAlg.BLS12_381_G2
        method = SeedMethod.BlsKeyGen
    # elif key_type == BLS12381G1G2:
    #     alg = KeyAlg.BLS12_381_G1G2
    else:
        raise WalletError(f"Unsupported key algorithm: {key_type}")
    if seed:
        try:
            if key_type in (ED25519, P256):
                # not a seed - it is the secret key
                seed = validate_seed(seed)
                return Key.from_secret_bytes(alg, seed)
            else:
                return Key.from_seed(alg, seed, method=method)
        except AskarError as err:
            if err.code == AskarErrorCode.INPUT:
                raise WalletError("Invalid seed for key generation") from err
            else:
                LOGGER.error(f"Unhandled Askar error code: {err.code}")
                raise
    else:
        return Key.generate(alg)
