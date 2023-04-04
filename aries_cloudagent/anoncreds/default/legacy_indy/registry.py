"""Legacy Indy Registry"""
from asyncio import shield
import json
import logging
import re
from typing import Optional, Pattern, Tuple
from urllib.parse import urlparse

from ....config.injection_context import InjectionContext
from ....core.profile import Profile
from ....ledger.base import BaseLedger
from ....ledger.error import (
    LedgerError,
    LedgerObjectAlreadyExistsError,
    LedgerTransactionError,
)
from ....ledger.merkel_validation.constants import GET_SCHEMA
from ....ledger.multiple_ledger.ledger_requests_executor import (
    GET_CRED_DEF,
    IndyLedgerRequestsExecutor,
)
from ....multitenant.base import BaseMultitenantManager
from ....revocation.anoncreds import AnonCredsRevocation
from ....revocation.error import RevocationError
from ....revocation.models.issuer_cred_rev_record import IssuerCredRevRecord
from ....revocation.recover import generate_ledger_rrrecovery_txn
from ....storage.error import StorageNotFoundError
from ...base import (
    AnonCredsObjectAlreadyExists,
    AnonCredsObjectNotFound,
    AnonCredsRegistrationError,
    AnonCredsResolutionError,
    AnonCredsSchemaAlreadyExists,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)
from ...issuer import AnonCredsIssuer, AnonCredsIssuerError
from ...models.anoncreds_cred_def import (
    CredDef,
    CredDefResult,
    CredDefState,
    CredDefValue,
    GetCredDefResult,
)
from ...models.anoncreds_revocation import (
    AnonCredsRegistryGetRevocationRegistryDefinition,
    GetRevStatusListResult,
    RevRegDef,
    RevRegDefResult,
    RevRegDefState,
    RevStatusList,
    RevStatusListResult,
    RevStatusListState,
)
from ...models.anoncreds_schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)

LOGGER = logging.getLogger(__name__)

DEFAULT_CRED_DEF_TAG = "default"
DEFAULT_SIGNATURE_TYPE = "CL"


class LegacyIndyRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """LegacyIndyRegistry"""

    def __init__(self):
        self._supported_identifiers_regex = re.compile(r"^(?!did).*$")
        # TODO: fix regex (too general)

    @property
    def supported_identifiers_regex(self) -> Pattern:
        return self._supported_identifiers_regex

    async def setup(self, context: InjectionContext):
        """Setup."""
        print("Successfully registered LegacyIndyRegistry")

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
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
            raise AnonCredsResolutionError(reason)

        async with ledger:
            try:
                schema = await ledger.get_schema(schema_id)
                if schema is None:
                    raise AnonCredsObjectNotFound(
                        f"Credential definition not found: {schema_id}",
                        {"ledger_id": ledger_id},
                    )

                anonscreds_schema = AnonCredsSchema(
                    issuer_id=schema["id"].split(":")[0],
                    attr_names=schema["attrNames"],
                    name=schema["name"],
                    version=schema["ver"],
                )
                result = GetSchemaResult(
                    schema=anonscreds_schema,
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

        schema_id = self.make_schema_id(schema)

        # Assume endorser role on the network, no option for 3rd-party endorser
        ledger = profile.inject_or(BaseLedger)
        if not ledger:
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                # TODO is this warning necessary?
                reason += ": missing wallet-type?"
            raise AnonCredsRegistrationError(reason)

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

        async with ledger:
            try:
                seq_no = await shield(ledger.send_schema(schema_id, indy_schema))
            except LedgerObjectAlreadyExistsError as err:
                indy_schema = err.obj[1]
                schema = AnonCredsSchema(
                    name=indy_schema["name"],
                    version=indy_schema["version"],
                    attr_names=indy_schema["attrNames"],
                    issuer_id=indy_schema["id"].split(":")[0],
                )
                raise AnonCredsSchemaAlreadyExists(err.message, (err.obj[0], schema))
            except (AnonCredsIssuerError, LedgerError) as err:
                raise AnonCredsRegistrationError("Failed to register schema") from err

        return SchemaResult(
            job_id=None,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={},
            schema_metadata={"seqNo": seq_no},
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
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
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

        cred_def_id = self.make_cred_def_id(schema, credential_definition)

        ledger = profile.inject_or(BaseLedger)
        if not ledger:
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
            raise AnonCredsRegistrationError(reason)

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

        try:
            async with ledger:
                seq_no = await shield(
                    ledger.send_credential_definition(
                        credential_definition.schema_id,
                        cred_def_id,
                        indy_cred_def,
                        write_ledger=True,
                        endorser_did=credential_definition.issuer_id,
                    )
                )
        except LedgerObjectAlreadyExistsError as err:
            if await issuer.credential_definition_in_wallet(cred_def_id):
                raise AnonCredsObjectAlreadyExists(
                    f"Credential definition with id {cred_def_id} "
                    "already exists in wallet and on ledger.",
                ) from err
            else:
                raise AnonCredsObjectAlreadyExists(
                    f"Credential definition {cred_def_id} is on "
                    f"ledger but not in wallet {profile.name}"
                ) from err
        except (AnonCredsIssuerError, LedgerError) as err:
            raise AnonCredsRegistrationError(
                "Failed to register credential definition"
            ) from err

        return CredDefResult(
            job_id=None,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_FINISHED,
                credential_definition_id=cred_def_id,
                credential_definition=credential_definition,
            ),
            registration_metadata={},
            credential_definition_metadata={"seqNo": seq_no, **(options or {})},
        )

    async def get_revocation_registry_definition(
        self, profile: Profile, rev_reg_id: str
    ) -> AnonCredsRegistryGetRevocationRegistryDefinition:
        """Get a revocation registry definition from the registry."""

        try:
            revoc = AnonCredsRevocation(profile)
            rev_reg = await revoc.get_issuer_rev_reg_record(rev_reg_id)
        except StorageNotFoundError as err:
            raise AnonCredsResolutionError(err)

        return rev_reg.serialize
        # use AnonCredsRevocationRegistryDefinition object

    async def get_revocation_registry_definitions(self, profile: Profile, filter: str):
        """Get credential definition ids filtered by filter"""

    def _check_url(self, url) -> None:
        parsed = urlparse(url)
        if not (parsed.scheme and parsed.netloc and parsed.path):
            raise RevocationError("URI {} is not a valid URL".format(url))

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""

        tails_base_url = profile.settings.get("tails_server_base_url")
        if not tails_base_url:
            raise AnonCredsRegistrationError("tails_server_base_url not configured")

        rev_reg_def_id = self.make_rev_reg_def_id(revocation_registry_definition)
        revocation_registry_definition.value.tails_location = (
            tails_base_url.rstrip("/") + f"/{rev_reg_def_id}"
        )

        try:
            self._check_url(revocation_registry_definition.value.tails_location)

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

            ledger = profile.inject(BaseLedger)
            async with ledger:
                resp = await ledger.send_revoc_reg_def(
                    indy_rev_reg_def,
                    revocation_registry_definition.issuer_id,
                )
            seq_no = resp["result"]["txnMetadata"]["seqNo"]
        except LedgerError as err:
            raise AnonCredsRegistrationError() from err

        return RevRegDefResult(
            job_id=None,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=rev_reg_def_id,
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata={},
            revocation_registry_definition_metadata={"seqNo": seq_no},
        )

    async def get_revocation_status_list(
        self, profile: Profile, revocation_registry_id: str, timestamp: str
    ) -> GetRevStatusListResult:
        """Get a revocation list from the registry."""

    async def register_revocation_status_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_status_list: RevStatusList,
        options: Optional[dict] = None,
    ) -> RevStatusListResult:
        """Register a revocation list on the registry."""
        # TODO Handle multitenancy and multi-ledger (like in get cred def)
        ledger = profile.inject(BaseLedger)

        rev_reg_entry = {"value": {"accum": rev_status_list.current_accumulator}}

        try:
            rev_entry_res = await ledger.send_revoc_reg_entry(
                rev_status_list.rev_reg_id,
                rev_reg_def.type,
                rev_reg_entry,
                rev_status_list.issuer_id,
                write_ledger=True,
                endorser_did=None,
            )
        except LedgerTransactionError as err:
            if "InvalidClientRequest" in err.roll_up:
                # ... if the ledger write fails (with "InvalidClientRequest")
                # e.g. aries_cloudagent.ledger.error.LedgerTransactionError:
                #   Ledger rejected transaction request: client request invalid:
                #   InvalidClientRequest(...)
                # In this scenario we try to post a correction
                LOGGER.warn("Retry ledger update/fix due to error")
                LOGGER.warn(err)
                (_, _, res) = await self.fix_ledger_entry(
                    profile,
                    rev_status_list,
                    True,
                    ledger.pool.genesis_txns,
                )
                rev_entry_res = {"result": res}
                LOGGER.warn("Ledger update/fix applied")
            elif "InvalidClientTaaAcceptanceError" in err.roll_up:
                # if no write access (with "InvalidClientTaaAcceptanceError")
                # e.g. aries_cloudagent.ledger.error.LedgerTransactionError:
                #   Ledger rejected transaction request: client request invalid:
                #   InvalidClientTaaAcceptanceError(...)
                LOGGER.exception("Ledger update failed due to TAA issue")
                raise AnonCredsRegistrationError(
                    "Ledger update failed due to TAA Issue"
                ) from err
            else:
                # not sure what happened, raise an error
                LOGGER.exception("Ledger update failed due to unknown issue")
                raise AnonCredsRegistrationError(
                    "Ledger update failed due to unknown issue"
                ) from err

        return RevStatusListResult(
            job_id=None,
            revocation_status_list_state=RevStatusListState(
                state=RevStatusListState.STATE_FINISHED,
                revocation_status_list=rev_status_list,
            ),
            registration_metadata={},
            revocation_status_list_metadata={
                "seqNo": rev_entry_res["result"]["txnMetadata"]["seqNo"],
            },
        )

    async def fix_ledger_entry(
        self,
        profile: Profile,
        rev_status_list: RevStatusList,
        apply_ledger_update: bool,
        genesis_transactions: str,
    ) -> Tuple[dict, dict, dict]:
        """Fix the ledger entry to match wallet-recorded credentials."""
        # get rev reg delta (revocations published to ledger)
        ledger = profile.inject(BaseLedger)
        async with ledger:
            (rev_reg_delta, _) = await ledger.get_revoc_reg_delta(
                rev_status_list.rev_reg_id
            )

        # get rev reg records from wallet (revocations and status)
        recs = []
        rec_count = 0
        accum_count = 0
        recovery_txn = {}
        applied_txn = {}
        async with profile.session() as session:
            recs = await IssuerCredRevRecord.query_by_ids(
                session, rev_reg_id=rev_status_list.rev_reg_id
            )

            revoked_ids = []
            for rec in recs:
                if rec.state == IssuerCredRevRecord.STATE_REVOKED:
                    revoked_ids.append(int(rec.cred_rev_id))
                    if int(rec.cred_rev_id) not in rev_reg_delta["value"]["revoked"]:
                        # await rec.set_state(session, IssuerCredRevRecord.STATE_ISSUED)
                        rec_count += 1

            LOGGER.debug(">>> fixed entry recs count = %s", rec_count)
            LOGGER.debug(
                ">>> rev_status_list.revocation_list: %s",
                rev_status_list.revocation_list,
            )
            LOGGER.debug(
                '>>> rev_reg_delta.get("value"): %s', rev_reg_delta.get("value")
            )

            # if we had any revocation discrepencies, check the accumulator value
            if rec_count > 0:
                if (
                    rev_status_list.current_accumulator and rev_reg_delta.get("value")
                ) and (
                    rev_status_list.current_accumulator
                    != rev_reg_delta["value"]["accum"]
                ):
                    # self.revoc_reg_entry = rev_reg_delta["value"]
                    # await self.save(session)
                    accum_count += 1

                calculated_txn = await generate_ledger_rrrecovery_txn(
                    genesis_transactions,
                    rev_status_list.rev_reg_id,
                    revoked_ids,
                )
                recovery_txn = json.loads(calculated_txn.to_json())

                LOGGER.debug(">>> apply_ledger_update = %s", apply_ledger_update)
                if apply_ledger_update:
                    ledger = session.inject_or(BaseLedger)
                    if not ledger:
                        reason = "No ledger available"
                        if not session.context.settings.get_value("wallet.type"):
                            reason += ": missing wallet-type?"
                        raise LedgerError(reason=reason)

                    async with ledger:
                        ledger_response = await ledger.send_revoc_reg_entry(
                            rev_status_list.rev_reg_id, "CL_ACCUM", recovery_txn
                        )

                    applied_txn = ledger_response["result"]

        return (rev_reg_delta, recovery_txn, applied_txn)
