"""Credential definition admin routes."""

import json

from asyncio import ensure_future, shield

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)

from marshmallow import fields

from ...admin.request_context import AdminRequestContext
from ...indy.issuer import IndyIssuer
from ...indy.sdk.models.cred_def import CredentialDefinitionSchema
from ...ledger.base import BaseLedger
from ...ledger.error import LedgerError
from ...protocols.endorse_transaction.v1_0.manager import TransactionManager
from ...protocols.endorse_transaction.v1_0.models.transaction_record import (
    TransactionRecordSchema,
)
from ...revocation.error import RevocationError, RevocationNotSupportedError
from ...revocation.indy import IndyRevocation
from ...storage.base import BaseStorage
from ...storage.error import StorageError
from ...tails.base import BaseTailsServer

from ..models.openapi import OpenAPISchema
from ..valid import INDY_CRED_DEF_ID, INDY_REV_REG_SIZE, INDY_SCHEMA_ID


from .util import CredDefQueryStringSchema, CRED_DEF_TAGS, CRED_DEF_SENT_RECORD_TYPE


from ..valid import UUIDFour
from ...connections.models.conn_record import ConnRecord
from ...storage.error import StorageNotFoundError
from ..models.base import BaseModelError


class CredentialDefinitionSendRequestSchema(OpenAPISchema):
    """Request schema for schema send request."""

    schema_id = fields.Str(description="Schema identifier", **INDY_SCHEMA_ID)
    support_revocation = fields.Boolean(
        required=False, description="Revocation supported flag"
    )
    revocation_registry_size = fields.Int(
        description="Revocation registry size",
        required=False,
        strict=True,
        **INDY_REV_REG_SIZE,
    )
    tag = fields.Str(
        required=False,
        description="Credential definition identifier tag",
        default="default",
        example="default",
    )


class CredentialDefinitionSendResultSchema(OpenAPISchema):
    """Result schema content for schema send request with auto-endorse."""

    credential_definition_id = fields.Str(
        description="Credential definition identifier", **INDY_CRED_DEF_ID
    )


class TxnOrCredentialDefinitionSendResultSchema(OpenAPISchema):
    """Result schema for credential definition send request."""

    sent = fields.Nested(
        CredentialDefinitionSendResultSchema(),
        required=False,
        definition="Content sent",
    )
    txn = fields.Nested(
        TransactionRecordSchema(),
        required=False,
        description="Credential definition transaction to endorse",
    )


class CredentialDefinitionGetResultSchema(OpenAPISchema):
    """Result schema for schema get request."""

    credential_definition = fields.Nested(CredentialDefinitionSchema)


class CredentialDefinitionsCreatedResultSchema(OpenAPISchema):
    """Result schema for cred-defs-created request."""

    credential_definition_ids = fields.List(
        fields.Str(description="Credential definition identifiers", **INDY_CRED_DEF_ID)
    )


class CredDefIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking cred def id."""

    cred_def_id = fields.Str(
        description="Credential definition identifier",
        required=True,
        **INDY_CRED_DEF_ID,
    )


class CreateTransactionForEndorserOptionSchema(OpenAPISchema):
    """Class for user to input whether to create a transaction for endorser or not."""

    create_transaction_for_endorser = fields.Boolean(
        description="Create Transaction For Endorser's signature",
        required=False,
    )


class ConnIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking connection id."""

    conn_id = fields.Str(
        description="Connection identifier", required=False, example=UUIDFour.EXAMPLE
    )


@docs(
    tags=["credential-definition"],
    summary="Sends a credential definition to the ledger",
)
@request_schema(CredentialDefinitionSendRequestSchema())
@querystring_schema(CreateTransactionForEndorserOptionSchema())
@querystring_schema(ConnIdMatchInfoSchema())
@response_schema(TxnOrCredentialDefinitionSendResultSchema(), 200, description="")
async def credential_definitions_send_credential_definition(request: web.BaseRequest):
    """
    Request handler for sending a credential definition to the ledger.

    Args:
        request: aiohttp request object

    Returns:
        The credential definition identifier

    """
    context: AdminRequestContext = request["context"]
    create_transaction_for_endorser = json.loads(
        request.query.get("create_transaction_for_endorser", "false")
    )
    write_ledger = not create_transaction_for_endorser
    endorser_did = None
    connection_id = request.query.get("conn_id")

    body = await request.json()

    schema_id = body.get("schema_id")
    support_revocation = bool(body.get("support_revocation"))
    tag = body.get("tag")
    rev_reg_size = body.get("revocation_registry_size")

    if not write_ledger:

        try:
            async with context.session() as session:
                connection_record = await ConnRecord.retrieve_by_id(
                    session, connection_id
                )
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err.roll_up) from err
        except BaseModelError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

        session = await context.session()
        endorser_info = await connection_record.metadata_get(session, "endorser_info")
        if not endorser_info:
            raise web.HTTPForbidden(
                reason="Endorser Info is not set up in "
                "connection metadata for this connection record"
            )
        if "endorser_did" not in endorser_info.keys():
            raise web.HTTPForbidden(
                reason=' "endorser_did" is not set in "endorser_info"'
                " in connection metadata for this connection record"
            )
        endorser_did = endorser_info["endorser_did"]

    ledger = context.inject(BaseLedger, required=False)
    if not ledger:
        reason = "No ledger available"
        if not context.settings.get_value("wallet.type"):
            reason += ": missing wallet-type?"
        raise web.HTTPForbidden(reason=reason)

    issuer = context.inject(IndyIssuer)
    try:  # even if in wallet, send it and raise if erroneously so
        async with ledger:
            (cred_def_id, cred_def, novel) = await shield(
                ledger.create_and_send_credential_definition(
                    issuer,
                    schema_id,
                    signature_type=None,
                    tag=tag,
                    support_revocation=support_revocation,
                    write_ledger=write_ledger,
                    endorser_did=endorser_did,
                )
            )

    except LedgerError as e:
        raise web.HTTPBadRequest(reason=e.message) from e

    # If revocation is requested and cred def is novel, create revocation registry
    if support_revocation and novel:
        profile = context.profile
        tails_base_url = profile.settings.get("tails_server_base_url")
        if not tails_base_url:
            raise web.HTTPBadRequest(reason="tails_server_base_url not configured")
        try:
            # Create registry
            revoc = IndyRevocation(profile)
            registry_record = await revoc.init_issuer_registry(
                cred_def_id,
                max_cred_num=rev_reg_size,
            )

        except RevocationNotSupportedError as e:
            raise web.HTTPBadRequest(reason=e.message) from e
        await shield(registry_record.generate_registry(profile))
        try:
            await registry_record.set_tails_file_public_uri(
                profile, f"{tails_base_url}/{registry_record.revoc_reg_id}"
            )
            await registry_record.send_def(profile)
            await registry_record.send_entry(profile)

            # stage pending registry independent of whether tails server is OK
            pending_registry_record = await revoc.init_issuer_registry(
                registry_record.cred_def_id,
                max_cred_num=registry_record.max_cred_num,
            )
            ensure_future(
                pending_registry_record.stage_pending_registry(profile, max_attempts=16)
            )

            tails_server = profile.inject(BaseTailsServer)
            (upload_success, reason) = await tails_server.upload_tails_file(
                profile,
                registry_record.revoc_reg_id,
                registry_record.tails_local_path,
                interval=0.8,
                backoff=-0.5,
                max_attempts=5,  # heuristic: respect HTTP timeout
            )
            if not upload_success:
                raise web.HTTPInternalServerError(
                    reason=(
                        f"Tails file for rev reg {registry_record.revoc_reg_id} "
                        f"failed to upload: {reason}"
                    )
                )

        except RevocationError as e:
            raise web.HTTPBadRequest(reason=e.message) from e

    if not create_transaction_for_endorser:
        return web.json_response({"sent": {"credential_definition_id": cred_def_id}})

    else:
        session = await context.session()

        transaction_mgr = TransactionManager(session)
        try:
            transaction = await transaction_mgr.create_record(
                messages_attach=cred_def["signed_txn"], connection_id=connection_id
            )
        except StorageError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

        return web.json_response({"txn": transaction.serialize()})


@docs(
    tags=["credential-definition"],
    summary="Search for matching credential definitions that agent originated",
)
@querystring_schema(CredDefQueryStringSchema())
@response_schema(CredentialDefinitionsCreatedResultSchema(), 200, description="")
async def credential_definitions_created(request: web.BaseRequest):
    """
    Request handler for retrieving credential definitions that current agent created.

    Args:
        request: aiohttp request object

    Returns:
        The identifiers of matching credential definitions.

    """
    context: AdminRequestContext = request["context"]

    session = await context.session()
    storage = session.inject(BaseStorage)
    found = await storage.find_all_records(
        type_filter=CRED_DEF_SENT_RECORD_TYPE,
        tag_query={
            tag: request.query[tag] for tag in CRED_DEF_TAGS if tag in request.query
        },
    )

    return web.json_response(
        {"credential_definition_ids": [record.value for record in found]}
    )


@docs(
    tags=["credential-definition"],
    summary="Gets a credential definition from the ledger",
)
@match_info_schema(CredDefIdMatchInfoSchema())
@response_schema(CredentialDefinitionGetResultSchema(), 200, description="")
async def credential_definitions_get_credential_definition(request: web.BaseRequest):
    """
    Request handler for getting a credential definition from the ledger.

    Args:
        request: aiohttp request object

    Returns:
        The credential definition details.

    """
    context: AdminRequestContext = request["context"]

    cred_def_id = request.match_info["cred_def_id"]

    ledger = context.inject(BaseLedger, required=False)
    if not ledger:
        reason = "No ledger available"
        if not context.settings.get_value("wallet.type"):
            reason += ": missing wallet-type?"
        raise web.HTTPForbidden(reason=reason)

    async with ledger:
        cred_def = await ledger.get_credential_definition(cred_def_id)

    return web.json_response({"credential_definition": cred_def})


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post(
                "/credential-definitions",
                credential_definitions_send_credential_definition,
            ),
            web.get(
                "/credential-definitions/created",
                credential_definitions_created,
                allow_head=False,
            ),
            web.get(
                "/credential-definitions/{cred_def_id}",
                credential_definitions_get_credential_definition,
                allow_head=False,
            ),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "credential-definition",
            "description": "Credential definition operations",
            "externalDocs": {
                "description": "Specification",
                "url": (
                    "https://github.com/hyperledger/indy-node/blob/master/"
                    "design/anoncreds.md#cred_def"
                ),
            },
        }
    )
