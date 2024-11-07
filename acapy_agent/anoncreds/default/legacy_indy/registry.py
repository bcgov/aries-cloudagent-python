"""Legacy Indy Registry."""

import asyncio
import logging
import re
from asyncio import shield
from typing import List, Optional, Pattern, Sequence, Tuple

from anoncreds import (
    CredentialDefinition,
    RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate,
)
from base58 import alphabet
from uuid_utils import uuid4

from ....anoncreds.default.legacy_indy.author import get_endorser_info
from ....cache.base import BaseCache
from ....config.injection_context import InjectionContext
from ....core.event_bus import EventBus
from ....core.profile import Profile, ProfileSession
from ....ledger.base import BaseLedger
from ....ledger.error import (
    LedgerError,
    LedgerObjectAlreadyExistsError,
    LedgerTransactionError,
)
from ....ledger.merkel_validation.constants import (
    GET_REVOC_REG_DELTA,
    GET_REVOC_REG_ENTRY,
    GET_SCHEMA,
)
from ....ledger.multiple_ledger.ledger_requests_executor import (
    GET_CRED_DEF,
    IndyLedgerRequestsExecutor,
)
from ....messaging.responder import BaseResponder
from ....multitenant.base import BaseMultitenantManager
from ....protocols.endorse_transaction.v1_0.manager import (
    TransactionManager,
    TransactionManagerError,
)
from ....protocols.endorse_transaction.v1_0.util import is_author_role
from ....revocation_anoncreds.models.issuer_cred_rev_record import IssuerCredRevRecord
from ....storage.error import StorageError
from ....utils import sentinel
from ....wallet.did_info import DIDInfo
from ...base import (
    AnonCredsObjectAlreadyExists,
    AnonCredsObjectNotFound,
    AnonCredsRegistrationError,
    AnonCredsResolutionError,
    AnonCredsSchemaAlreadyExists,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)
from ...events import RevListFinishedEvent
from ...issuer import CATEGORY_CRED_DEF, AnonCredsIssuer, AnonCredsIssuerError
from ...models.credential_definition import (
    CredDef,
    CredDefResult,
    CredDefState,
    CredDefValue,
    GetCredDefResult,
)
from ...models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevListState,
    RevRegDef,
    RevRegDefResult,
    RevRegDefState,
    RevRegDefValue,
)
from ...models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from ...models.schema_info import AnoncredsSchemaInfo
from ...revocation import (
    CATEGORY_REV_LIST,
    CATEGORY_REV_REG_DEF,
    CATEGORY_REV_REG_DEF_PRIVATE,
)
from .recover import generate_ledger_rrrecovery_txn

LOGGER = logging.getLogger(__name__)

# Defaults
DEFAULT_CRED_DEF_TAG = "default"
DEFAULT_SIGNATURE_TYPE = "CL"

# Common error messages
NO_LEDGER_AVAILABLE_MSG = "No ledger available"
MISSING_WALLET_TYPE_MSG = ": missing wallet-type?"
TRANSACTION_MANAGER_FAILED_MSG = "Transaction manager failed to create request: "
FAILED_TO_STORE_TRANSACTION_RECORD = "Failed to store transaction record"

# Common settings
ENDORSER_AUTO = "endorser.auto_request"
WALLET_TYPE = "wallet.type"


class LegacyIndyRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """LegacyIndyRegistry."""

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """
        B58 = alphabet if isinstance(alphabet, str) else alphabet.decode("ascii")
        INDY_DID = rf"^(did:sov:)?[{B58}]{{21,22}}$"
        INDY_SCHEMA_ID = rf"^[{B58}]{{21,22}}:2:.+:[0-9.]+$"
        # the schema id can be just a number
        # (this is how the schema_id is referenced in a cred def)
        INDY_SCHEMA_TXN_ID = r"^[0-9.]+$"
        INDY_CRED_DEF_ID = (
            rf"^([{B58}]{{21,22}})"  # issuer DID
            f":3"  # cred def id marker
            f":CL"  # sig alg
            rf":(([1-9][0-9]*)|([{B58}]{{21,22}}:2:.+:[0-9.]+))"  # schema txn / id
            f":(.+)?$"  # tag
        )
        INDY_REV_REG_DEF_ID = (
            rf"^([{B58}]{{21,22}}):4:"
            rf"([{B58}]{{21,22}}):3:"
            rf"CL:(([1-9][0-9]*)|([{B58}]{{21,22}}:2:.+:[0-9.]+))(:.+)?:"
            rf"CL_ACCUM:(.+$)"
        )
        self._supported_identifiers_regex = re.compile(
            rf"{INDY_DID}|{INDY_SCHEMA_ID}|{INDY_SCHEMA_TXN_ID}|{INDY_CRED_DEF_ID}|{INDY_REV_REG_DEF_ID}"
        )

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers Regular Expression."""
        return self._supported_identifiers_regex

    async def setup(self, context: InjectionContext):
        """Setup."""
        LOGGER.info("Successfully registered LegacyIndyRegistry")

    @staticmethod
    def make_schema_id(schema: AnonCredsSchema) -> str:
        """Derive the ID for a schema."""
        return f"{schema.issuer_id}:2:{schema.name}:{schema.version}"

    @staticmethod
    def make_cred_def_id(
        schema: GetSchemaResult,
        cred_def: CredDef,
    ) -> str:
        """Derive the ID for a credential definition."""
        signature_type = cred_def.type or DEFAULT_SIGNATURE_TYPE
        tag = cred_def.tag or DEFAULT_CRED_DEF_TAG

        try:
            seq_no = str(schema.schema_metadata["seqNo"])
        except KeyError as err:
            raise AnonCredsRegistrationError(
                "Legacy Indy only supports schemas from Legacy Indy"
            ) from err

        return f"{cred_def.issuer_id}:3:{signature_type}:{seq_no}:{tag}"

    @staticmethod
    def make_rev_reg_def_id(rev_reg_def: RevRegDef) -> str:
        """Derive the ID for a revocation registry definition."""
        return (
            f"{rev_reg_def.issuer_id}:4:{rev_reg_def.cred_def_id}:"
            f"{rev_reg_def.type}:{rev_reg_def.tag}"
        )

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""

        multitenant_mgr = profile.inject_or(BaseMultitenantManager)
        if multitenant_mgr:
            ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
        else:
            ledger_exec_inst = profile.inject(IndyLedgerRequestsExecutor)
        ledger_id, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            schema_id,
            txn_record_type=GET_SCHEMA,
        )

        if not ledger:
            reason = NO_LEDGER_AVAILABLE_MSG
            if not profile.settings.get_value(WALLET_TYPE):
                reason += MISSING_WALLET_TYPE_MSG
            raise AnonCredsResolutionError(reason)

        async with ledger:
            try:
                schema = await ledger.get_schema(schema_id)
                if schema is None:
                    raise AnonCredsObjectNotFound(
                        f"Schema not found: {schema_id}",
                        {"ledger_id": ledger_id},
                    )

                anoncreds_schema = AnonCredsSchema(
                    issuer_id=schema["id"].split(":")[0],
                    attr_names=schema["attrNames"],
                    name=schema["name"],
                    version=schema["version"],
                )
                result = GetSchemaResult(
                    schema=anoncreds_schema,
                    schema_id=schema["id"],
                    resolution_metadata={"ledger_id": ledger_id},
                    schema_metadata={"seqNo": schema["seqNo"]},
                )
            except LedgerError as err:
                raise AnonCredsResolutionError("Failed to retrieve schema") from err

        return result

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        options = options or {}
        schema_id = self.make_schema_id(schema)

        # Assume endorser role on the network, no option for 3rd-party endorser
        ledger = profile.inject_or(BaseLedger)
        if not ledger:
            raise AnonCredsRegistrationError(NO_LEDGER_AVAILABLE_MSG)

        # Translate schema into format expected by Indy
        LOGGER.debug("Registering schema: %s", schema_id)
        indy_schema = {
            "ver": "1.0",
            "id": schema_id,
            "name": schema.name,
            "version": schema.version,
            "attrNames": schema.attr_names,
            "seqNo": None,
        }
        LOGGER.debug("schema value: %s", indy_schema)

        endorser_did = None
        create_transaction = options.get("create_transaction_for_endorser", False)

        if is_author_role(profile) or create_transaction:
            endorser_did, endorser_connection_id = await get_endorser_info(
                profile, options
            )

        write_ledger = True if endorser_did is None and not create_transaction else False

        # Get either the transaction or the seq_no or the created schema
        async with ledger:
            try:
                result = await shield(
                    ledger.send_schema_anoncreds(
                        schema_id,
                        indy_schema,
                        write_ledger=write_ledger,
                        endorser_did=endorser_did,
                    )
                )
            except LedgerObjectAlreadyExistsError as err:
                raise AnonCredsSchemaAlreadyExists(err.message, err.obj_id, schema)
            except (AnonCredsIssuerError, LedgerError) as err:
                raise AnonCredsRegistrationError("Failed to register schema") from err

        # Didn't need endorsement, so return schema result
        if write_ledger:
            return SchemaResult(
                job_id=None,
                schema_state=SchemaState(
                    state=SchemaState.STATE_FINISHED,
                    schema_id=schema_id,
                    schema=schema,
                ),
                registration_metadata={},
                schema_metadata={"seqNo": result},
            )

        # Need endorsement, so execute transaction flow
        (schema_id, schema_def) = result

        job_id = uuid4().hex
        meta_data = {"context": {"job_id": job_id, "schema_id": schema_id}}

        transaction_manager = TransactionManager(profile)
        try:
            transaction = await transaction_manager.create_record(
                messages_attach=schema_def["signed_txn"],
                connection_id=endorser_connection_id,
                meta_data=meta_data,
            )
        except StorageError:
            raise AnonCredsRegistrationError(FAILED_TO_STORE_TRANSACTION_RECORD)

        if profile.settings.get(ENDORSER_AUTO):
            try:
                (
                    transaction,
                    transaction_request,
                ) = await transaction_manager.create_request(transaction=transaction)
            except (StorageError, TransactionManagerError) as err:
                raise AnonCredsRegistrationError(
                    TRANSACTION_MANAGER_FAILED_MSG + err.roll_up
                ) from err

            responder = profile.inject(BaseResponder)
            await responder.send(
                message=transaction_request,
                connection_id=endorser_connection_id,
            )

        return SchemaResult(
            job_id=job_id,
            schema_state=SchemaState(
                state=SchemaState.STATE_WAIT,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={
                "txn": transaction.serialize(),
            },
        )

    async def get_credential_definition(
        self, profile: Profile, cred_def_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""

        async with profile.session() as session:
            multitenant_mgr = session.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
            else:
                ledger_exec_inst = session.inject(IndyLedgerRequestsExecutor)

        ledger_id, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            cred_def_id,
            txn_record_type=GET_CRED_DEF,
        )
        if not ledger:
            reason = NO_LEDGER_AVAILABLE_MSG
            if not profile.settings.get_value(WALLET_TYPE):
                reason += MISSING_WALLET_TYPE_MSG
            raise AnonCredsResolutionError(reason)

        async with ledger:
            cred_def = await ledger.get_credential_definition(cred_def_id)

            if cred_def is None:
                raise AnonCredsObjectNotFound(
                    f"Credential definition not found: {cred_def_id}",
                    {"ledger_id": ledger_id},
                )

            cred_def_value = CredDefValue.deserialize(cred_def["value"])
            anoncreds_credential_definition = CredDef(
                issuer_id=cred_def["id"].split(":")[0],
                schema_id=cred_def["schemaId"],
                type=cred_def["type"],
                tag=cred_def["tag"],
                value=cred_def_value,
            )
            anoncreds_registry_get_credential_definition = GetCredDefResult(
                credential_definition=anoncreds_credential_definition,
                credential_definition_id=cred_def["id"],
                resolution_metadata={},
                credential_definition_metadata={},
            )
        return anoncreds_registry_get_credential_definition

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        options = options or {}
        cred_def_id = self.make_cred_def_id(schema, credential_definition)

        ledger = profile.inject_or(BaseLedger)
        if not ledger:
            raise AnonCredsRegistrationError(NO_LEDGER_AVAILABLE_MSG)

        # Check if in wallet but not on ledger
        issuer = AnonCredsIssuer(profile)
        if await issuer.credential_definition_in_wallet(cred_def_id):
            try:
                await self.get_credential_definition(profile, cred_def_id)
            except AnonCredsObjectNotFound as err:
                raise AnonCredsRegistrationError(
                    f"Credential definition with id {cred_def_id} already "
                    "exists in wallet but not on the ledger"
                ) from err

        # Translate anoncreds object to indy object
        LOGGER.debug("Registering credential definition: %s", cred_def_id)
        indy_cred_def = {
            "id": cred_def_id,
            "schemaId": str(schema.schema_metadata["seqNo"]),
            "tag": credential_definition.tag,
            "type": credential_definition.type,
            "value": credential_definition.value.serialize(),
            "ver": "1.0",
        }
        LOGGER.debug("Cred def value: %s", indy_cred_def)

        endorser_did = None
        create_transaction = options.get("create_transaction_for_endorser", False)

        if is_author_role(profile) or create_transaction:
            endorser_did, endorser_connection_id = await get_endorser_info(
                profile, options
            )

        write_ledger = True if endorser_did is None and not create_transaction else False

        async with ledger:
            try:
                result = await shield(
                    ledger.send_credential_definition_anoncreds(
                        credential_definition.schema_id,
                        cred_def_id,
                        indy_cred_def,
                        write_ledger=write_ledger,
                        endorser_did=endorser_did,
                    )
                )
            except LedgerObjectAlreadyExistsError as err:
                if await issuer.credential_definition_in_wallet(cred_def_id):
                    raise AnonCredsObjectAlreadyExists(
                        f"Credential definition with id {cred_def_id} "
                        "already exists in wallet and on ledger.",
                        cred_def_id,
                    ) from err
                else:
                    raise AnonCredsObjectAlreadyExists(
                        f"Credential definition {cred_def_id} is on "
                        f"ledger but not in wallet {profile.name}",
                        cred_def_id,
                    ) from err

        # Didn't need endorsement
        if write_ledger:
            return CredDefResult(
                job_id=None,
                credential_definition_state=CredDefState(
                    state=CredDefState.STATE_FINISHED,
                    credential_definition_id=cred_def_id,
                    credential_definition=credential_definition,
                ),
                registration_metadata={},
                credential_definition_metadata={"seqNo": result},
            )

        # Need endorsement, so execute transaction flow
        job_id = uuid4().hex

        meta_data = {
            "context": {
                "job_id": job_id,
                "cred_def_id": cred_def_id,
                "options": options,
            },
        }

        (cred_def_id, cred_def) = result
        transaction_manager = TransactionManager(profile)

        try:
            transaction = await transaction_manager.create_record(
                messages_attach=cred_def["signed_txn"],
                connection_id=endorser_connection_id,
                meta_data=meta_data,
            )
        except StorageError:
            raise AnonCredsRegistrationError(FAILED_TO_STORE_TRANSACTION_RECORD)

        if profile.settings.get(ENDORSER_AUTO):
            try:
                (
                    transaction,
                    transaction_request,
                ) = await transaction_manager.create_request(transaction=transaction)
            except (StorageError, TransactionManagerError) as err:
                raise AnonCredsRegistrationError(
                    TRANSACTION_MANAGER_FAILED_MSG + err.roll_up
                ) from err

            responder = profile.inject(BaseResponder)
            await responder.send(
                message=transaction_request,
                connection_id=endorser_connection_id,
            )

        return CredDefResult(
            job_id=job_id,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_WAIT,
                credential_definition_id=cred_def_id,
                credential_definition=credential_definition,
            ),
            registration_metadata={
                "txn": transaction.serialize(),
            },
            credential_definition_metadata={},
        )

    async def get_revocation_registry_definition(
        self, profile: Profile, rev_reg_def_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        async with profile.session() as session:
            multitenant_mgr = session.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
            else:
                ledger_exec_inst = session.inject(IndyLedgerRequestsExecutor)

        ledger_id, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            rev_reg_def_id,
            txn_record_type=GET_CRED_DEF,
        )
        if not ledger:
            reason = NO_LEDGER_AVAILABLE_MSG
            if not profile.settings.get_value(WALLET_TYPE):
                reason += MISSING_WALLET_TYPE_MSG
            raise AnonCredsResolutionError(reason)

        async with ledger:
            rev_reg_def = await ledger.get_revoc_reg_def(rev_reg_def_id)

            if rev_reg_def is None:
                raise AnonCredsObjectNotFound(
                    f"Revocation registry definition not found: {rev_reg_def_id}",
                    {"ledger_id": ledger_id},
                )

            LOGGER.debug("Retrieved revocation registry definition: %s", rev_reg_def)
            rev_reg_def_value = RevRegDefValue.deserialize(rev_reg_def["value"])
            anoncreds_rev_reg_def = RevRegDef(
                issuer_id=rev_reg_def["id"].split(":")[0],
                cred_def_id=rev_reg_def["credDefId"],
                type=rev_reg_def["revocDefType"],
                value=rev_reg_def_value,
                tag=rev_reg_def["tag"],
            )
            result = GetRevRegDefResult(
                revocation_registry=anoncreds_rev_reg_def,
                revocation_registry_id=rev_reg_def["id"],
                resolution_metadata={},
                revocation_registry_metadata={},
            )

        return result

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""
        options = options or {}
        rev_reg_def_id = self.make_rev_reg_def_id(revocation_registry_definition)

        ledger = profile.inject(BaseLedger)
        if not ledger:
            raise AnonCredsRegistrationError(NO_LEDGER_AVAILABLE_MSG)

        # Translate anoncreds object to indy object
        indy_rev_reg_def = {
            "ver": "1.0",
            "id": rev_reg_def_id,
            "revocDefType": revocation_registry_definition.type,
            "credDefId": revocation_registry_definition.cred_def_id,
            "tag": revocation_registry_definition.tag,
            "value": {
                "issuanceType": "ISSUANCE_BY_DEFAULT",
                "maxCredNum": revocation_registry_definition.value.max_cred_num,
                "publicKeys": revocation_registry_definition.value.public_keys,
                "tailsHash": revocation_registry_definition.value.tails_hash,
                "tailsLocation": revocation_registry_definition.value.tails_location,
            },
        }

        endorser_did = None
        create_transaction = options.get(
            "create_transaction_for_endorser", False
        ) or profile.settings.get("endorser.auto_create_rev_reg", False)

        if is_author_role(profile) or create_transaction:
            endorser_did, endorser_connection_id = await get_endorser_info(
                profile, options
            )

        write_ledger = True if endorser_did is None and not create_transaction else False

        try:
            async with ledger:
                result = await ledger.send_revoc_reg_def(
                    indy_rev_reg_def,
                    revocation_registry_definition.issuer_id,
                    write_ledger=write_ledger,
                    endorser_did=endorser_did,
                )
        except LedgerError as err:
            LOGGER.error(
                f"Error registering revocation registry definition {rev_reg_def_id}: {err.roll_up}"  # noqa: E501
            )

        # Didn't need endorsement
        if write_ledger:
            return RevRegDefResult(
                job_id=None,
                revocation_registry_definition_state=RevRegDefState(
                    state=RevRegDefState.STATE_FINISHED,
                    revocation_registry_definition_id=rev_reg_def_id,
                    revocation_registry_definition=revocation_registry_definition,
                ),
                registration_metadata={},
                revocation_registry_definition_metadata={"seqNo": result},
            )

        # Need endorsement, so execute transaction flow
        (rev_reg_def_id, reg_rev_def) = result

        job_id = uuid4().hex
        meta_data = {
            "context": {
                "job_id": job_id,
                "rev_reg_def_id": rev_reg_def_id,
                "options": options,
            }
        }

        transaction_manager = TransactionManager(profile)
        try:
            transaction = await transaction_manager.create_record(
                messages_attach=reg_rev_def["signed_txn"],
                connection_id=endorser_connection_id,
                meta_data=meta_data,
            )
        except StorageError:
            raise AnonCredsRegistrationError(FAILED_TO_STORE_TRANSACTION_RECORD)

        if profile.settings.get(ENDORSER_AUTO):
            try:
                (
                    transaction,
                    transaction_request,
                ) = await transaction_manager.create_request(transaction=transaction)
            except (StorageError, TransactionManagerError) as err:
                raise AnonCredsRegistrationError(
                    TRANSACTION_MANAGER_FAILED_MSG + err.roll_up
                ) from err

            responder = profile.inject(BaseResponder)
            await responder.send(
                message=transaction_request,
                connection_id=endorser_connection_id,
            )

        return RevRegDefResult(
            job_id=job_id,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_WAIT,
                revocation_registry_definition_id=rev_reg_def_id,
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata={
                "txn": transaction.serialize(),
            },
            revocation_registry_definition_metadata={},
        )

    async def _get_or_fetch_rev_reg_def_max_cred_num(
        self, profile: Profile, ledger: BaseLedger, rev_reg_def_id: str
    ) -> int:
        """Retrieve max cred num for a rev reg def.

        The value is retrieved from cache or from the ledger if necessary.
        The issuer could retrieve this value from the wallet but this info
        must also be known to the holder.
        """
        cache = profile.inject(BaseCache)
        cache_key = f"anoncreds::legacy_indy::rev_reg_max_cred_num::{rev_reg_def_id}"

        if cache:
            max_cred_num = await cache.get(cache_key)
            if max_cred_num:
                return max_cred_num

        rev_reg_def = await ledger.get_revoc_reg_def(rev_reg_def_id)
        max_cred_num = rev_reg_def["value"]["maxCredNum"]

        if cache:
            await cache.set(cache_key, max_cred_num)

        return max_cred_num

    def _indexes_to_bit_array(self, indexes: List[int], size: int) -> List[int]:
        """Turn a sequence of indexes into a full state bit array."""
        return [1 if index in indexes else 0 for index in range(0, size + 1)]

    async def _get_ledger(self, profile: Profile, rev_reg_def_id: str):
        async with profile.session() as session:
            multitenant_mgr = session.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
            else:
                ledger_exec_inst = session.inject(IndyLedgerRequestsExecutor)

        ledger_id, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            rev_reg_def_id,
            txn_record_type=GET_CRED_DEF,
        )
        if not ledger:
            reason = NO_LEDGER_AVAILABLE_MSG
            if not profile.settings.get_value(WALLET_TYPE):
                reason += MISSING_WALLET_TYPE_MSG
            raise AnonCredsResolutionError(reason)

        return ledger_id, ledger

    async def get_revocation_registry_delta(
        self,
        profile: Profile,
        rev_reg_def_id: str,
        timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
    ) -> Tuple[dict, int]:
        """Fetch the revocation registry delta."""
        ledger_id, ledger = await self._get_ledger(profile, rev_reg_def_id)

        async with ledger:
            delta, timestamp = await ledger.get_revoc_reg_delta(
                rev_reg_def_id, timestamp_from=timestamp_from, timestamp_to=timestamp_to
            )

            if delta is None:
                raise AnonCredsObjectNotFound(
                    f"Revocation list not found for rev reg def: {rev_reg_def_id}",
                    {"ledger_id": ledger_id},
                )
        LOGGER.debug("Retrieved delta: %s", delta)
        return delta, timestamp

    async def get_revocation_list(
        self,
        profile: Profile,
        rev_reg_def_id: str,
        timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
    ) -> GetRevListResult:
        """Get the revocation registry list."""
        _, ledger = await self._get_ledger(profile, rev_reg_def_id)

        delta, timestamp = await self.get_revocation_registry_delta(
            profile, rev_reg_def_id, timestamp_from, timestamp_to
        )

        async with ledger:
            max_cred_num = await self._get_or_fetch_rev_reg_def_max_cred_num(
                profile, ledger, rev_reg_def_id
            )
            revocation_list_from_indexes = self._indexes_to_bit_array(
                delta["value"]["revoked"], max_cred_num
            )
            LOGGER.debug(
                "Index list to full state bit array: %s", revocation_list_from_indexes
            )
            rev_list = RevList(
                issuer_id=rev_reg_def_id.split(":")[0],
                rev_reg_def_id=rev_reg_def_id,
                revocation_list=revocation_list_from_indexes,
                current_accumulator=delta["value"]["accum"],
                timestamp=timestamp,
            )
            result = GetRevListResult(
                revocation_list=rev_list,
                resolution_metadata={},
                revocation_registry_metadata={},
            )

        return result

    async def _revoc_reg_entry_with_fix(
        self,
        profile: Profile,
        rev_list: RevList,
        rev_reg_def_type: str,
        entry: dict,
        write_ledger: bool,
        endorser_did: Optional[str] = None,
    ) -> dict:
        """Send a revocation registry entry to the ledger with fixes if needed."""
        multitenant_mgr = profile.inject_or(BaseMultitenantManager)
        if multitenant_mgr:
            ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
        else:
            ledger_exec_inst = profile.inject(IndyLedgerRequestsExecutor)
        _, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            rev_list.rev_reg_def_id,
            txn_record_type=GET_REVOC_REG_ENTRY,
        )

        try:
            async with ledger:
                rev_entry_res = await ledger.send_revoc_reg_entry(
                    rev_list.rev_reg_def_id,
                    rev_reg_def_type,
                    entry,
                    rev_list.issuer_id,
                    write_ledger=write_ledger,
                    endorser_did=endorser_did,
                )
        except LedgerTransactionError as err:
            if "InvalidClientRequest" in err.roll_up:
                # ... if the ledger write fails (with "InvalidClientRequest")
                # e.g. acapy_agent.ledger.error.LedgerTransactionError:
                #   Ledger rejected transaction request: client request invalid:
                #   InvalidClientRequest(...)
                # In this scenario we try to post a correction
                LOGGER.warning("Retry ledger update/fix due to error")
                LOGGER.warning(err)
                (_, _, rev_entry_res) = await self.fix_ledger_entry(
                    profile,
                    rev_list,
                    True,
                    ledger.pool.genesis_txns,
                    write_ledger,
                    endorser_did,
                )
                LOGGER.warning("Ledger update/fix applied")
            elif "InvalidClientTaaAcceptanceError" in err.roll_up:
                # if no write access (with "InvalidClientTaaAcceptanceError")
                # e.g. acapy_agent.ledger.error.LedgerTransactionError:
                #   Ledger rejected transaction request: client request invalid:
                #   InvalidClientTaaAcceptanceError(...)
                LOGGER.exception("Ledger update failed due to TAA issue")
                raise AnonCredsRegistrationError(
                    "Ledger update failed due to TAA Issue"
                ) from err
            else:
                LOGGER.exception("Ledger update failed due to unknown issue")
                raise AnonCredsRegistrationError(
                    "Ledger update failed due to unknown issue"
                ) from err

        return rev_entry_res

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        options = options or {}
        rev_reg_entry = {"ver": "1.0", "value": {"accum": rev_list.current_accumulator}}

        endorser_did = None
        create_transaction = options.get(
            "create_transaction_for_endorser", False
        ) or profile.settings.get("endorser.auto_create_rev_reg", False)

        if is_author_role(profile) or create_transaction:
            endorser_did, endorser_connection_id = await get_endorser_info(
                profile, options
            )

        write_ledger = True if endorser_did is None and not create_transaction else False

        result = await self._revoc_reg_entry_with_fix(
            profile,
            rev_list,
            rev_reg_def.type,
            rev_reg_entry,
            write_ledger,
            endorser_did,
        )

        if write_ledger:
            return RevListResult(
                job_id=None,
                revocation_list_state=RevListState(
                    state=RevListState.STATE_FINISHED,
                    revocation_list=rev_list,
                ),
                registration_metadata={},
                revocation_list_metadata={"seqNo": result},
            )

        (rev_reg_def_id, requested_txn) = result

        job_id = uuid4().hex
        meta_data = {
            "context": {
                "job_id": job_id,
                "rev_reg_def_id": rev_reg_def_id,
                "options": {
                    "endorser_connection_id": endorser_connection_id,
                    "create_transaction_for_endorser": create_transaction,
                },
            }
        }

        transaction_manager = TransactionManager(profile)
        try:
            transaction = await transaction_manager.create_record(
                messages_attach=requested_txn["signed_txn"],
                connection_id=endorser_connection_id,
                meta_data=meta_data,
            )
        except StorageError:
            raise AnonCredsRegistrationError(FAILED_TO_STORE_TRANSACTION_RECORD)

        if profile.settings.get(ENDORSER_AUTO):
            try:
                (
                    transaction,
                    transaction_request,
                ) = await transaction_manager.create_request(transaction=transaction)
            except (StorageError, TransactionManagerError) as err:
                raise AnonCredsRegistrationError(
                    TRANSACTION_MANAGER_FAILED_MSG + err.roll_up
                ) from err

            responder = profile.inject(BaseResponder)
            await responder.send(
                message=transaction_request,
                connection_id=endorser_connection_id,
            )

        return RevListResult(
            job_id=job_id,
            revocation_list_state=RevListState(
                state=RevListState.STATE_WAIT,
                revocation_list=rev_list,
            ),
            registration_metadata={
                "txn": transaction.serialize(),
            },
            revocation_list_metadata={},
        )

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        prev_list: RevList,
        curr_list: RevList,
        revoked: Sequence[int],
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list."""
        options = options or {}
        newly_revoked_indices = list(revoked)
        rev_reg_entry = {
            "ver": "1.0",
            "value": {
                "accum": curr_list.current_accumulator,
                "prevAccum": prev_list.current_accumulator,
                "revoked": newly_revoked_indices,
            },
        }

        endorser_did = None
        create_transaction = options.get("create_transaction_for_endorser", False)

        if is_author_role(profile) or create_transaction:
            endorser_did, endorser_connection_id = await get_endorser_info(
                profile, options
            )

        write_ledger = True if endorser_did is None and not create_transaction else False

        result = await self._revoc_reg_entry_with_fix(
            profile,
            curr_list,
            rev_reg_def.type,
            rev_reg_entry,
            write_ledger,
            endorser_did,
        )

        if write_ledger:
            event_bus = profile.inject(EventBus)
            await event_bus.notify(
                profile,
                RevListFinishedEvent.with_payload(
                    curr_list.rev_reg_def_id, newly_revoked_indices
                ),
            )
            return RevListResult(
                job_id=None,
                revocation_list_state=RevListState(
                    state=RevListState.STATE_FINISHED,
                    revocation_list=curr_list,
                ),
                registration_metadata={},
                revocation_list_metadata={"seqNo": result},
            )

        (rev_reg_def_id, requested_txn) = result

        job_id = uuid4().hex
        meta_data = {
            "context": {
                "job_id": job_id,
                "rev_reg_def_id": rev_reg_def_id,
                "rev_list": curr_list.serialize(),
                "options": {
                    "endorser_connection_id": endorser_connection_id,
                    "create_transaction_for_endorser": create_transaction,
                },
            }
        }

        transaction_manager = TransactionManager(profile)
        try:
            transaction = await transaction_manager.create_record(
                messages_attach=requested_txn["signed_txn"],
                connection_id=endorser_connection_id,
                meta_data=meta_data,
            )
        except StorageError:
            raise AnonCredsRegistrationError(FAILED_TO_STORE_TRANSACTION_RECORD)

        if profile.settings.get(ENDORSER_AUTO):
            try:
                (
                    transaction,
                    transaction_request,
                ) = await transaction_manager.create_request(transaction=transaction)
            except (StorageError, TransactionManagerError) as err:
                raise AnonCredsRegistrationError(
                    TRANSACTION_MANAGER_FAILED_MSG + err.roll_up
                ) from err

            responder = profile.inject(BaseResponder)
            await responder.send(
                message=transaction_request,
                connection_id=endorser_connection_id,
            )

        return RevListResult(
            job_id=job_id,
            revocation_list_state=RevListState(
                state=RevListState.STATE_WAIT,
                revocation_list=curr_list,
            ),
            registration_metadata={
                "txn": transaction.serialize(),
            },
            revocation_list_metadata={},
        )

    async def fix_ledger_entry(
        self,
        profile: Profile,
        rev_list: RevList,
        apply_ledger_update: bool,
        genesis_transactions: str,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
    ) -> Tuple[dict, dict, dict]:
        """Fix the ledger entry to match wallet-recorded credentials."""

        def _wallet_accumalator_matches_ledger_list(
            rev_list: RevList, rev_reg_delta: dict
        ) -> bool:
            return (
                rev_reg_delta.get("value")
                and rev_list.current_accumulator == rev_reg_delta["value"]["accum"]
            )

        applied_txn = {}
        recovery_txn = {}

        LOGGER.debug("Fixing ledger entry for revocation list...")

        multitenant_mgr = profile.inject_or(BaseMultitenantManager)
        if multitenant_mgr:
            ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
        else:
            ledger_exec_inst = profile.inject(IndyLedgerRequestsExecutor)
        _, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            rev_list.rev_reg_def_id,
            txn_record_type=GET_REVOC_REG_DELTA,
        )

        async with ledger:
            (rev_reg_delta, _) = await ledger.get_revoc_reg_delta(rev_list.rev_reg_def_id)

        async with profile.session() as session:
            LOGGER.debug(f"revocation_list = {rev_list.revocation_list}")
            LOGGER.debug(f"rev_reg_delta = {rev_reg_delta.get('value')}")

            rev_list = await self._sync_wallet_rev_list_with_issuer_cred_rev_records(
                session, rev_list
            )

            if not _wallet_accumalator_matches_ledger_list(rev_list, rev_reg_delta):
                recovery_txn = await generate_ledger_rrrecovery_txn(
                    genesis_transactions, rev_list
                )

                if apply_ledger_update and recovery_txn:
                    ledger = session.inject_or(BaseLedger)
                    if not ledger:
                        reason = NO_LEDGER_AVAILABLE_MSG
                        if not session.context.settings.get_value(WALLET_TYPE):
                            reason += MISSING_WALLET_TYPE_MSG
                        raise LedgerError(reason=reason)

                    async with ledger:
                        applied_txn = await ledger.send_revoc_reg_entry(
                            rev_list.rev_reg_def_id,
                            "CL_ACCUM",
                            recovery_txn,
                            rev_list.issuer_id,
                            write_ledger,
                            endorser_did,
                        )

        return (rev_reg_delta, recovery_txn, applied_txn)

    async def _sync_wallet_rev_list_with_issuer_cred_rev_records(
        self, session: ProfileSession, rev_list: RevList
    ) -> RevList:
        """Sync the wallet revocation list with the issuer cred rev records."""

        async def _revoked_issuer_cred_rev_record_ids() -> List[int]:
            cred_rev_records = await IssuerCredRevRecord.query_by_ids(
                session, rev_reg_id=rev_list.rev_reg_def_id
            )
            return [
                int(rec.cred_rev_id) for rec in cred_rev_records if rec.state == "revoked"
            ]

        def _revocation_list_to_array_of_indexes(
            revocation_list: List[int],
        ) -> List[int]:
            return [index for index, value in enumerate(revocation_list) if value == 1]

        revoked = await _revoked_issuer_cred_rev_record_ids()
        if revoked == _revocation_list_to_array_of_indexes(rev_list.revocation_list):
            return rev_list

        # The revocation list is out of sync with the issuer cred rev records
        # Recreate the revocation list with the issuer cred rev records
        revoc_reg_def_entry = await session.handle.fetch(
            CATEGORY_REV_REG_DEF, rev_list.rev_reg_def_id
        )
        cred_def_entry = await session.handle.fetch(
            CATEGORY_CRED_DEF,
            RevRegDef.deserialize(revoc_reg_def_entry.value_json).cred_def_id,
        )
        revoc_reg_def_private_entry = await session.handle.fetch(
            CATEGORY_REV_REG_DEF_PRIVATE, rev_list.rev_reg_def_id
        )
        updated_list = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: rev_list.to_native().update(
                cred_def=CredentialDefinition.load(cred_def_entry.value_json),
                rev_reg_def=RevocationRegistryDefinition.load(
                    revoc_reg_def_entry.value_json
                ),
                rev_reg_def_private=RevocationRegistryDefinitionPrivate.load(
                    revoc_reg_def_private_entry.raw_value
                ),
                issued=None,
                revoked=revoked,
                timestamp=None,
            ),
        )
        rev_list_entry_update = await session.handle.fetch(
            CATEGORY_REV_LIST, rev_list.rev_reg_def_id, for_update=True
        )
        tags = rev_list_entry_update.tags
        rev_list_entry_update = rev_list_entry_update.value_json
        rev_list_entry_update["rev_list"] = updated_list.to_dict()

        await session.handle.replace(
            CATEGORY_REV_LIST,
            rev_list.rev_reg_def_id,
            value_json=rev_list_entry_update,
            tags=tags,
        )
        return RevList.deserialize(updated_list.to_json())

    async def txn_submit(
        self,
        ledger: BaseLedger,
        ledger_transaction: str,
        sign: Optional[bool] = None,
        taa_accept: Optional[bool] = None,
        sign_did: DIDInfo = sentinel,
        write_ledger: bool = True,
    ) -> str:
        """Submit a transaction to the ledger."""

        try:
            async with ledger:
                return await shield(
                    ledger.txn_submit(
                        ledger_transaction,
                        sign=sign,
                        taa_accept=taa_accept,
                        sign_did=sign_did,
                        write_ledger=write_ledger,
                    )
                )
        except LedgerError as err:
            raise AnonCredsRegistrationError(err.roll_up) from err

    async def get_schema_info_by_id(
        self, profile: Profile, schema_id: str
    ) -> AnoncredsSchemaInfo:
        """Get schema info by schema id."""
        schema_id_parts = re.match(r"^(\w+):2:([^:]+):([^:]+)$", schema_id)
        return AnoncredsSchemaInfo(
            issuer_id=schema_id_parts.group(1),
            name=schema_id_parts.group(2),
            version=schema_id_parts.group(3),
        )
