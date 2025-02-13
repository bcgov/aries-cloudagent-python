"""Indy issuer implementation."""

import asyncio
import logging
from typing import Optional, Sequence, Tuple

from aries_askar import AskarError
from indy_credx import (
    Credential,
    CredentialDefinition,
    CredentialOffer,
    CredentialRevocationConfig,
    CredxError,
    RevocationRegistry,
    RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate,
    RevocationRegistryDelta,
    Schema,
)

from ...askar.profile import AskarProfile
from ...utils.general import strip_did_prefix
from ..issuer import (
    DEFAULT_CRED_DEF_TAG,
    DEFAULT_SIGNATURE_TYPE,
    IndyIssuer,
    IndyIssuerError,
    IndyIssuerRevocationRegistryFullError,
)

LOGGER = logging.getLogger(__name__)

CATEGORY_CRED_DEF = "credential_def"
CATEGORY_CRED_DEF_PRIVATE = "credential_def_private"
CATEGORY_CRED_DEF_KEY_PROOF = "credential_def_key_proof"
CATEGORY_SCHEMA = "schema"
CATEGORY_REV_REG = "revocation_reg"
CATEGORY_REV_REG_INFO = "revocation_reg_info"
CATEGORY_REV_REG_DEF = "revocation_reg_def"
CATEGORY_REV_REG_DEF_PRIVATE = "revocation_reg_def_private"
CATEGORY_REV_REG_ISSUER = "revocation_reg_def_issuer"


class IndyCredxIssuer(IndyIssuer):
    """Indy-Credx issuer class."""

    def __init__(self, profile: AskarProfile):
        """Initialize an IndyCredxIssuer instance.

        Args:
            profile: The active profile instance

        """
        self._profile = profile

    @property
    def profile(self) -> AskarProfile:
        """Accessor for the profile instance."""
        return self._profile

    async def create_schema(
        self,
        origin_did: str,
        schema_name: str,
        schema_version: str,
        attribute_names: Sequence[str],
    ) -> Tuple[str, str]:
        """Create a new credential schema and store it in the wallet.

        Args:
            origin_did: the DID issuing the credential definition
            schema_name: the schema name
            schema_version: the schema version
            attribute_names: a sequence of schema attribute names

        Returns:
            A tuple of the schema ID and JSON

        """
        try:
            schema = Schema.create(
                strip_did_prefix(origin_did),
                schema_name,
                schema_version,
                attribute_names,
            )
            schema_id = schema.id
            schema_json = schema.to_json()
            async with self._profile.session() as session:
                await session.handle.insert(CATEGORY_SCHEMA, schema_id, schema_json)
        except CredxError as err:
            raise IndyIssuerError("Error creating schema") from err
        except AskarError as err:
            raise IndyIssuerError("Error storing schema") from err
        return (schema_id, schema_json)

    async def credential_definition_in_wallet(
        self, credential_definition_id: str
    ) -> bool:
        """Check whether a given credential definition ID is present in the wallet.

        Args:
            credential_definition_id: The credential definition ID to check
        """
        try:
            async with self._profile.session() as session:
                return (
                    await session.handle.fetch(
                        CATEGORY_CRED_DEF_PRIVATE, credential_definition_id
                    )
                ) is not None
        except AskarError as err:
            raise IndyIssuerError("Error checking for credential definition") from err

    async def create_and_store_credential_definition(
        self,
        origin_did: str,
        schema: dict,
        signature_type: Optional[str] = None,
        tag: Optional[str] = None,
        support_revocation: bool = False,
    ) -> Tuple[str, str]:
        """Create a new credential definition and store it in the wallet.

        Args:
            origin_did (str): The DID issuing the credential definition.
            schema (dict): The schema to create a credential definition for.
            signature_type (str, optional): The credential definition signature type
                (default 'CL').
            tag (str, optional): The credential definition tag.
            support_revocation (bool, optional): Whether to enable revocation for this
                credential definition.

        Returns:
            Tuple[str, str]: A tuple of the credential definition ID and JSON.

        Raises:
            IndyIssuerError: If there is an error creating or storing the credential
                definition.

        """
        try:
            (
                cred_def,
                cred_def_private,
                key_proof,
            ) = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: CredentialDefinition.create(
                    strip_did_prefix(origin_did),
                    schema,
                    signature_type or DEFAULT_SIGNATURE_TYPE,
                    tag or DEFAULT_CRED_DEF_TAG,
                    support_revocation=support_revocation,
                ),
            )
            cred_def_id = cred_def.id
            cred_def_json = cred_def.to_json()
        except CredxError as err:
            raise IndyIssuerError("Error creating credential definition") from err
        try:
            async with self._profile.transaction() as txn:
                await txn.handle.insert(
                    CATEGORY_CRED_DEF,
                    cred_def_id,
                    cred_def_json,
                    # Note: Indy-SDK uses a separate SchemaId record for this
                    tags={"schema_id": schema["id"]},
                )
                await txn.handle.insert(
                    CATEGORY_CRED_DEF_PRIVATE,
                    cred_def_id,
                    cred_def_private.to_json_buffer(),
                )
                await txn.handle.insert(
                    CATEGORY_CRED_DEF_KEY_PROOF, cred_def_id, key_proof.to_json_buffer()
                )
                await txn.commit()
        except AskarError as err:
            raise IndyIssuerError("Error storing credential definition") from err
        return (cred_def_id, cred_def_json)

    async def create_credential_offer(self, credential_definition_id: str) -> str:
        """Create a credential offer for the given credential definition id.

        Args:
            credential_definition_id: The credential definition to create an offer for

        Returns:
            The new credential offer

        """
        try:
            async with self._profile.session() as session:
                cred_def = await session.handle.fetch(
                    CATEGORY_CRED_DEF, credential_definition_id
                )
                key_proof = await session.handle.fetch(
                    CATEGORY_CRED_DEF_KEY_PROOF, credential_definition_id
                )
        except AskarError as err:
            raise IndyIssuerError("Error retrieving credential definition") from err
        if not cred_def or not key_proof:
            raise IndyIssuerError("Credential definition not found for credential offer")
        try:
            # The tag holds the full name of the schema,
            # as opposed to just the sequence number
            schema_id = cred_def.tags.get("schema_id")
            cred_def = CredentialDefinition.load(cred_def.raw_value)

            credential_offer = CredentialOffer.create(
                schema_id or cred_def.schema_id,
                cred_def,
                key_proof.raw_value,
            )
        except CredxError as err:
            raise IndyIssuerError("Error creating credential offer") from err

        return credential_offer.to_json()

    async def create_credential(
        self,
        schema: dict,
        credential_offer: dict,
        credential_request: dict,
        credential_values: dict,
        revoc_reg_id: Optional[str] = None,
        tails_file_path: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Create a credential.

        Args:
            schema: Schema to create credential for
            credential_offer: Credential Offer to create credential for
            credential_request: Credential request to create credential for
            credential_values: Values to go in credential
            revoc_reg_id: ID of the revocation registry
            tails_file_path: The location of the tails file

        Returns:
            A tuple of created credential and revocation id

        """
        credential_definition_id = credential_offer["cred_def_id"]
        try:
            async with self._profile.session() as session:
                cred_def = await session.handle.fetch(
                    CATEGORY_CRED_DEF, credential_definition_id
                )
                cred_def_private = await session.handle.fetch(
                    CATEGORY_CRED_DEF_PRIVATE, credential_definition_id
                )
        except AskarError as err:
            raise IndyIssuerError("Error retrieving credential definition") from err
        if not cred_def or not cred_def_private:
            raise IndyIssuerError(
                "Credential definition not found for credential issuance"
            )

        raw_values = {}
        schema_attributes = schema["attrNames"]
        for attribute in schema_attributes:
            # Ensure every attribute present in schema to be set.
            # Extraneous attribute names are ignored.
            try:
                credential_value = credential_values[attribute]
            except KeyError:
                raise IndyIssuerError(
                    "Provided credential values are missing a value "
                    f"for the schema attribute '{attribute}'"
                )

            raw_values[attribute] = str(credential_value)

        if revoc_reg_id:
            try:
                async with self._profile.transaction() as txn:
                    rev_reg = await txn.handle.fetch(CATEGORY_REV_REG, revoc_reg_id)
                    rev_reg_info = await txn.handle.fetch(
                        CATEGORY_REV_REG_INFO, revoc_reg_id, for_update=True
                    )
                    rev_reg_def = await txn.handle.fetch(
                        CATEGORY_REV_REG_DEF, revoc_reg_id
                    )
                    rev_key = await txn.handle.fetch(
                        CATEGORY_REV_REG_DEF_PRIVATE, revoc_reg_id
                    )
                    if not rev_reg:
                        raise IndyIssuerError("Revocation registry not found")
                    if not rev_reg_info:
                        raise IndyIssuerError("Revocation registry metadata not found")
                    if not rev_reg_def:
                        raise IndyIssuerError("Revocation registry definition not found")
                    if not rev_key:
                        raise IndyIssuerError(
                            "Revocation registry definition private data not found"
                        )
                    # NOTE: we increment the index ahead of time to keep the
                    # transaction short. The revocation registry itself will NOT
                    # be updated because we always use ISSUANCE_BY_DEFAULT.
                    # If something goes wrong later, the index will be skipped.
                    # FIXME - double check issuance type in case of upgraded wallet?
                    rev_info = rev_reg_info.value_json
                    rev_reg_index = rev_info["curr_id"] + 1
                    try:
                        rev_reg_def = RevocationRegistryDefinition.load(
                            rev_reg_def.raw_value
                        )
                    except CredxError as err:
                        raise IndyIssuerError(
                            "Error loading revocation registry definition"
                        ) from err
                    if rev_reg_index > rev_reg_def.max_cred_num:
                        raise IndyIssuerRevocationRegistryFullError(
                            "Revocation registry is full"
                        )
                    rev_info["curr_id"] = rev_reg_index
                    await txn.handle.replace(
                        CATEGORY_REV_REG_INFO, revoc_reg_id, value_json=rev_info
                    )
                    await txn.commit()
            except AskarError as err:
                raise IndyIssuerError("Error updating revocation registry index") from err

            revoc = CredentialRevocationConfig(
                rev_reg_def,
                rev_key.raw_value,
                rev_reg.raw_value,
                rev_reg_index,
                rev_info.get("used_ids") or [],
            )
            credential_revocation_id = str(rev_reg_index)
        else:
            revoc = None
            credential_revocation_id = None

        # This is for compatibility with an anoncreds holder
        if not credential_request.get("prover_did"):
            credential_request["prover_did"] = credential_request["entropy"]
            del credential_request["entropy"]

        try:
            (
                credential,
                _upd_rev_reg,
                _delta,
            ) = await asyncio.get_event_loop().run_in_executor(
                None,
                Credential.create,
                cred_def.raw_value,
                cred_def_private.raw_value,
                credential_offer,
                credential_request,
                raw_values,
                None,
                revoc,
            )
        except CredxError as err:
            raise IndyIssuerError("Error creating credential") from err

        return credential.to_json(), credential_revocation_id

    async def revoke_credentials(
        self,
        cred_def_id: str,
        revoc_reg_id: str,
        tails_file_path: str,
        cred_revoc_ids: Sequence[str],
    ) -> Tuple[str, Sequence[str]]:
        """Revoke a set of credentials in a revocation registry.

        Args:
            cred_def_id: ID of the credential definition
            revoc_reg_id: ID of the revocation registry
            tails_file_path: path to the local tails file
            cred_revoc_ids: sequences of credential indexes in the revocation registry

        Returns:
            Tuple with the combined revocation delta, list of cred rev ids not revoked

        """

        delta = None
        failed_crids = set()
        max_attempt = 5
        attempt = 0

        while True:
            attempt += 1
            if attempt >= max_attempt:
                raise IndyIssuerError("Repeated conflict attempting to update registry")
            try:
                async with self._profile.session() as session:
                    cred_def = await session.handle.fetch(CATEGORY_CRED_DEF, cred_def_id)
                    rev_reg_def = await session.handle.fetch(
                        CATEGORY_REV_REG_DEF, revoc_reg_id
                    )
                    rev_reg_def_private = await session.handle.fetch(
                        CATEGORY_REV_REG_DEF_PRIVATE, revoc_reg_id
                    )
                    rev_reg = await session.handle.fetch(CATEGORY_REV_REG, revoc_reg_id)
                    rev_reg_info = await session.handle.fetch(
                        CATEGORY_REV_REG_INFO, revoc_reg_id
                    )
                if not cred_def:
                    raise IndyIssuerError("Credential definition not found")
                if not rev_reg_def:
                    raise IndyIssuerError("Revocation registry definition not found")
                if not rev_reg_def_private:
                    raise IndyIssuerError(
                        "Revocation registry definition private key not found"
                    )
                if not rev_reg:
                    raise IndyIssuerError("Revocation registry not found")
                if not rev_reg_info:
                    raise IndyIssuerError("Revocation registry metadata not found")
            except AskarError as err:
                raise IndyIssuerError("Error retrieving revocation registry") from err

            try:
                cred_def = CredentialDefinition.load(cred_def.raw_value)
            except CredxError as err:
                raise IndyIssuerError("Error loading credential definition") from err

            try:
                rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def.raw_value)
            except CredxError as err:
                raise IndyIssuerError(
                    "Error loading revocation registry definition"
                ) from err

            try:
                rev_reg_def_private = RevocationRegistryDefinitionPrivate.load(
                    rev_reg_def_private.raw_value
                )
            except CredxError as err:
                raise IndyIssuerError(
                    "Error loading revocation registry private key"
                ) from err

            try:
                rev_reg = RevocationRegistry.load(rev_reg.raw_value)
            except CredxError as err:
                raise IndyIssuerError("Error loading revocation registry") from err

            rev_crids = set()
            failed_crids = set()
            max_cred_num = rev_reg_def.max_cred_num
            rev_info = rev_reg_info.value_json
            used_ids = set(rev_info.get("used_ids") or [])

            for rev_id in cred_revoc_ids:
                rev_id = int(rev_id)
                if rev_id < 1 or rev_id > max_cred_num:
                    LOGGER.error(
                        "Skipping requested credential revocation"
                        "on rev reg id %s, cred rev id=%s not in range",
                        revoc_reg_id,
                        rev_id,
                    )
                    failed_crids.add(rev_id)
                elif rev_id > rev_info["curr_id"]:
                    LOGGER.warning(
                        "Skipping requested credential revocation"
                        "on rev reg id %s, cred rev id=%s not yet issued",
                        revoc_reg_id,
                        rev_id,
                    )
                    failed_crids.add(rev_id)
                elif rev_id in used_ids:
                    LOGGER.warning(
                        "Skipping requested credential revocation"
                        "on rev reg id %s, cred rev id=%s already revoked",
                        revoc_reg_id,
                        rev_id,
                    )
                    failed_crids.add(rev_id)
                else:
                    rev_crids.add(rev_id)

            if not rev_crids:
                break

            try:
                delta = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: rev_reg.update(
                        cred_def,
                        rev_reg_def,
                        rev_reg_def_private,
                        issued=None,
                        revoked=list(rev_crids),  # revoked
                    ),
                )
            except CredxError as err:
                raise IndyIssuerError("Error updating revocation registry") from err

            try:
                async with self._profile.transaction() as txn:
                    rev_reg_upd = await txn.handle.fetch(
                        CATEGORY_REV_REG, revoc_reg_id, for_update=True
                    )
                    rev_info_upd = await txn.handle.fetch(
                        CATEGORY_REV_REG_INFO, revoc_reg_id, for_update=True
                    )
                    if not rev_reg_upd or not rev_reg_info:
                        LOGGER.warning(
                            "Revocation registry missing, skipping update: {}",
                            revoc_reg_id,
                        )
                        delta = None
                        break
                    rev_info_upd = rev_info_upd.value_json
                    if rev_info_upd != rev_info:
                        # handle concurrent update to the registry by retrying
                        continue
                    await txn.handle.replace(
                        CATEGORY_REV_REG, revoc_reg_id, rev_reg.to_json_buffer()
                    )
                    used_ids.update(rev_crids)
                    rev_info_upd["used_ids"] = sorted(used_ids)
                    await txn.handle.replace(
                        CATEGORY_REV_REG_INFO, revoc_reg_id, value_json=rev_info_upd
                    )
                    await txn.commit()
            except AskarError as err:
                raise IndyIssuerError("Error saving revocation registry") from err
            break

        return (
            delta and delta.to_json(),
            [str(rev_id) for rev_id in sorted(failed_crids)],
        )

    async def merge_revocation_registry_deltas(
        self, fro_delta: str, to_delta: str
    ) -> str:
        """Merge revocation registry deltas.

        Args:
            fro_delta: original delta in JSON format
            to_delta: incoming delta in JSON format

        Returns:
            Merged delta in JSON format

        """

        def update(d1, d2):
            try:
                delta = RevocationRegistryDelta.load(d1)
                delta.update_with(d2)
                return delta.to_json()
            except CredxError as err:
                raise IndyIssuerError("Error merging revocation registry deltas") from err

        return await asyncio.get_event_loop().run_in_executor(
            None, update, fro_delta, to_delta
        )

    async def create_and_store_revocation_registry(
        self,
        origin_did: str,
        cred_def_id: str,
        revoc_def_type: str,
        tag: str,
        max_cred_num: int,
        tails_base_path: str,
    ) -> Tuple[str, str, str]:
        """Create a new revocation registry and store it in the wallet.

        Args:
            origin_did: the DID issuing the revocation registry
            cred_def_id: the identifier of the related credential definition
            revoc_def_type: the revocation registry type (default CL_ACCUM)
            tag: the unique revocation registry tag
            max_cred_num: the number of credentials supported in the registry
            tails_base_path: where to store the tails file
            issuance_type: optionally override the issuance type

        Returns:
            A tuple of the revocation registry ID, JSON, and entry JSON

        """
        try:
            async with self._profile.session() as session:
                cred_def = await session.handle.fetch(CATEGORY_CRED_DEF, cred_def_id)
        except AskarError as err:
            raise IndyIssuerError("Error retrieving credential definition") from err
        if not cred_def:
            raise IndyIssuerError(
                "Credential definition not found for revocation registry"
            )

        try:
            (
                rev_reg_def,
                rev_reg_def_private,
                rev_reg,
                _rev_reg_delta,
            ) = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: RevocationRegistryDefinition.create(
                    strip_did_prefix(origin_did),
                    cred_def.raw_value,
                    tag,
                    revoc_def_type,
                    max_cred_num,
                    tails_dir_path=tails_base_path,
                ),
            )
        except CredxError as err:
            raise IndyIssuerError("Error creating revocation registry") from err

        rev_reg_def_id = rev_reg_def.id
        rev_reg_def_json = rev_reg_def.to_json()
        rev_reg_json = rev_reg.to_json()

        try:
            async with self._profile.transaction() as txn:
                await txn.handle.insert(CATEGORY_REV_REG, rev_reg_def_id, rev_reg_json)
                await txn.handle.insert(
                    CATEGORY_REV_REG_INFO,
                    rev_reg_def_id,
                    value_json={"curr_id": 0, "used_ids": []},
                )
                await txn.handle.insert(
                    CATEGORY_REV_REG_DEF, rev_reg_def_id, rev_reg_def_json
                )
                await txn.handle.insert(
                    CATEGORY_REV_REG_DEF_PRIVATE,
                    rev_reg_def_id,
                    rev_reg_def_private.to_json_buffer(),
                )
                await txn.commit()
        except AskarError as err:
            raise IndyIssuerError("Error saving new revocation registry") from err

        return (
            rev_reg_def_id,
            rev_reg_def_json,
            rev_reg_json,
        )
