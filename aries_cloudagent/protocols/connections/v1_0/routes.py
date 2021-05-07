"""Connection handling admin routes."""

import json

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)

from marshmallow import fields, validate, validates_schema

from ....admin.request_context import AdminRequestContext
from ....connections.models.conn_record import ConnRecord, ConnRecordSchema
from ....messaging.models.base import BaseModelError
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import (
    ENDPOINT,
    GENERIC_DID,
    INDY_RAW_PUBLIC_KEY,
    UUIDFour,
)
from ....storage.error import StorageError, StorageNotFoundError
from ....wallet.error import WalletError

from .manager import ConnectionManager, ConnectionManagerError
from .message_types import SPEC_URI
from .messages.connection_invitation import (
    ConnectionInvitation,
    ConnectionInvitationSchema,
)


class ConnectionModuleResponseSchema(OpenAPISchema):
    """Response schema for connection module."""


class ConnectionListSchema(OpenAPISchema):
    """Result schema for connection list."""

    results = fields.List(
        fields.Nested(ConnRecordSchema()),
        description="List of connection records",
    )


class ConnectionMetadataSchema(OpenAPISchema):
    """Result schema for connection metadata."""

    results = fields.Dict(
        description="Dictionary of metadata associated with connection.",
    )


class ConnectionMetadataSetRequestSchema(OpenAPISchema):
    """Request Schema for set metadata."""

    metadata = fields.Dict(
        required=True,
        description="Dictionary of metadata to set for connection.",
    )


class ConnectionMetadataQuerySchema(OpenAPISchema):
    """Query schema for metadata."""

    key = fields.Str(required=False, description="Key to retrieve.")


class ReceiveInvitationRequestSchema(ConnectionInvitationSchema):
    """Request schema for receive invitation request."""

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Bypass middleware field validation: marshmallow has no data yet."""


MEDIATION_ID_SCHEMA = {
    "validate": UUIDFour(),
    "example": UUIDFour.EXAMPLE,
}


class CreateInvitationRequestSchema(OpenAPISchema):
    """Request schema for invitation connection target."""

    recipient_keys = fields.List(
        fields.Str(description="Recipient public key", **INDY_RAW_PUBLIC_KEY),
        required=False,
        description="List of recipient keys",
    )
    service_endpoint = fields.Str(
        required=False,
        description="Connection endpoint",
        example="http://192.168.56.102:8020",
    )
    routing_keys = fields.List(
        fields.Str(description="Routing key", **INDY_RAW_PUBLIC_KEY),
        required=False,
        description="List of routing keys",
    )
    my_label = fields.Str(
        description="Optional label for connection invitation",
        required=False,
        example="Bob",
    )
    metadata = fields.Dict(
        description="Optional metadata to attach to the connection created with "
        "the invitation",
        required=False,
    )
    mediation_id = fields.Str(
        required=False,
        description="Identifier for active mediation record to be used",
        **MEDIATION_ID_SCHEMA
    )


class InvitationResultSchema(OpenAPISchema):
    """Result schema for a new connection invitation."""

    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE
    )
    invitation = fields.Nested(ConnectionInvitationSchema())
    invitation_url = fields.Str(
        description="Invitation URL",
        example="http://192.168.56.101:8020/invite?c_i=eyJAdHlwZSI6Li4ufQ==",
    )


class ConnectionStaticRequestSchema(OpenAPISchema):
    """Request schema for a new static connection."""

    my_seed = fields.Str(description="Seed to use for the local DID", required=False)
    my_did = fields.Str(description="Local DID", required=False, **GENERIC_DID)
    their_seed = fields.Str(
        description="Seed to use for the remote DID", required=False
    )
    their_did = fields.Str(description="Remote DID", required=False, **GENERIC_DID)
    their_verkey = fields.Str(description="Remote verification key", required=False)
    their_endpoint = fields.Str(
        description="URL endpoint for other party", required=False, **ENDPOINT
    )
    their_label = fields.Str(
        description="Other party's label for this connection", required=False
    )
    alias = fields.Str(description="Alias to assign to this connection", required=False)


class ConnectionStaticResultSchema(OpenAPISchema):
    """Result schema for new static connection."""

    my_did = fields.Str(description="Local DID", required=True, **GENERIC_DID)
    mv_verkey = fields.Str(
        description="My verification key", required=True, **INDY_RAW_PUBLIC_KEY
    )
    my_endpoint = fields.Str(description="My URL endpoint", required=True, **ENDPOINT)
    their_did = fields.Str(description="Remote DID", required=True, **GENERIC_DID)
    their_verkey = fields.Str(
        description="Remote verification key", required=True, **INDY_RAW_PUBLIC_KEY
    )
    record = fields.Nested(ConnRecordSchema, required=True)


class ConnectionsListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for connections list request query string."""

    alias = fields.Str(
        description="Alias",
        required=False,
        example="Barry",
    )
    invitation_key = fields.Str(
        description="invitation key", required=False, **INDY_RAW_PUBLIC_KEY
    )
    my_did = fields.Str(description="My DID", required=False, **GENERIC_DID)
    state = fields.Str(
        description="Connection state",
        required=False,
        validate=validate.OneOf(
            {label for state in ConnRecord.State for label in state.value}
        ),
    )
    their_did = fields.Str(description="Their DID", required=False, **GENERIC_DID)
    their_role = fields.Str(
        description="Their role in the connection protocol",
        required=False,
        validate=validate.OneOf(
            [label for role in ConnRecord.Role for label in role.value]
        ),
        example=ConnRecord.Role.REQUESTER.rfc160,
    )


class CreateInvitationQueryStringSchema(OpenAPISchema):
    """Parameters and validators for create invitation request query string."""

    alias = fields.Str(
        description="Alias",
        required=False,
        example="Barry",
    )
    auto_accept = fields.Boolean(
        description="Auto-accept connection (defaults to configuration)",
        required=False,
    )
    public = fields.Boolean(
        description="Create invitation from public DID (default false)", required=False
    )
    multi_use = fields.Boolean(
        description="Create invitation for multiple use (default false)", required=False
    )


class ReceiveInvitationQueryStringSchema(OpenAPISchema):
    """Parameters and validators for receive invitation request query string."""

    alias = fields.Str(
        description="Alias",
        required=False,
        example="Barry",
    )
    auto_accept = fields.Boolean(
        description="Auto-accept connection (defaults to configuration)",
        required=False,
    )
    mediation_id = fields.Str(
        required=False,
        description="Identifier for active mediation record to be used",
        **MEDIATION_ID_SCHEMA
    )


class AcceptInvitationQueryStringSchema(OpenAPISchema):
    """Parameters and validators for accept invitation request query string."""

    my_endpoint = fields.Str(description="My URL endpoint", required=False, **ENDPOINT)
    my_label = fields.Str(
        description="Label for connection", required=False, example="Broker"
    )
    mediation_id = fields.Str(
        required=False,
        description="Identifier for active mediation record to be used",
        **MEDIATION_ID_SCHEMA
    )


class AcceptRequestQueryStringSchema(OpenAPISchema):
    """Parameters and validators for accept conn-request web-request query string."""

    my_endpoint = fields.Str(description="My URL endpoint", required=False, **ENDPOINT)


class ConnIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking connection id."""

    conn_id = fields.Str(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )


class ConnIdRefIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking connection and ref ids."""

    conn_id = fields.Str(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )

    ref_id = fields.Str(
        description="Inbound connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
    )


class EndpointsResultSchema(OpenAPISchema):
    """Result schema for connection endpoints."""

    my_endpoint = fields.Str(description="My endpoint", **ENDPOINT)
    their_endpoint = fields.Str(description="Their endpoint", **ENDPOINT)


def connection_sort_key(conn):
    """Get the sorting key for a particular connection."""

    conn_rec_state = ConnRecord.State.get(conn["state"])
    if conn_rec_state is ConnRecord.State.ABANDONED:
        pfx = "2"
    elif conn_rec_state is ConnRecord.State.INVITATION:
        pfx = "1"
    else:
        pfx = "0"

    return pfx + conn["created_at"]


@docs(
    tags=["connection"],
    summary="Query agent-to-agent connections",
)
@querystring_schema(ConnectionsListQueryStringSchema())
@response_schema(ConnectionListSchema(), 200, description="")
async def connections_list(request: web.BaseRequest):
    """
    Request handler for searching connection records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context: AdminRequestContext = request["context"]

    tag_filter = {}
    for param_name in (
        "invitation_id",
        "my_did",
        "their_did",
        "request_id",
    ):
        if param_name in request.query and request.query[param_name] != "":
            tag_filter[param_name] = request.query[param_name]

    post_filter = {}
    if request.query.get("alias"):
        post_filter["alias"] = request.query["alias"]
    if request.query.get("state"):
        post_filter["state"] = [
            v for v in ConnRecord.State.get(request.query["state"]).value
        ]
    if request.query.get("their_role"):
        post_filter["their_role"] = [
            v for v in ConnRecord.Role.get(request.query["their_role"]).value
        ]

    session = await context.session()
    try:
        records = await ConnRecord.query(
            session, tag_filter, post_filter_positive=post_filter, alt=True
        )
        results = [record.serialize() for record in records]
        results.sort(key=connection_sort_key)
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=["connection"], summary="Fetch a single connection record")
@match_info_schema(ConnIdMatchInfoSchema())
@response_schema(ConnRecordSchema(), 200, description="")
async def connections_retrieve(request: web.BaseRequest):
    """
    Request handler for fetching a single connection record.

    Args:
        request: aiohttp request object

    Returns:
        The connection record response

    """
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    session = await context.session()

    try:
        record = await ConnRecord.retrieve_by_id(session, connection_id)
        result = record.serialize()
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except BaseModelError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(tags=["connection"], summary="Fetch connection remote endpoint")
@match_info_schema(ConnIdMatchInfoSchema())
@response_schema(EndpointsResultSchema(), 200, description="")
async def connections_endpoints(request: web.BaseRequest):
    """
    Request handler for fetching connection endpoints.

    Args:
        request: aiohttp request object

    Returns:
        The endpoints response

    """
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    session = await context.session()

    connection_mgr = ConnectionManager(session)
    try:
        endpoints = await connection_mgr.get_endpoints(connection_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, StorageError, WalletError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(dict(zip(("my_endpoint", "their_endpoint"), endpoints)))


@docs(tags=["connection"], summary="Fetch connection metadata")
@match_info_schema(ConnIdMatchInfoSchema())
@querystring_schema(ConnectionMetadataQuerySchema())
@response_schema(ConnectionMetadataSchema(), 200, description="")
async def connections_metadata(request: web.BaseRequest):
    """Handle fetching metadata associated with a single connection record."""
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    key = request.query.get("key", None)
    session = await context.session()

    try:
        record = await ConnRecord.retrieve_by_id(session, connection_id)
        if key:
            result = await record.metadata_get(session, key)
        else:
            result = await record.metadata_get_all(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except BaseModelError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": result})


@docs(tags=["connection"], summary="Set connection metadata")
@match_info_schema(ConnIdMatchInfoSchema())
@request_schema(ConnectionMetadataSetRequestSchema())
@response_schema(ConnectionMetadataSchema(), 200, description="")
async def connections_metadata_set(request: web.BaseRequest):
    """Handle fetching metadata associated with a single connection record."""
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    body = await request.json() if request.body_exists else {}
    session = await context.session()

    try:
        record = await ConnRecord.retrieve_by_id(session, connection_id)
        for key, value in body.get("metadata", {}).items():
            await record.metadata_set(session, key, value)
        result = await record.metadata_get_all(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except BaseModelError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": result})


@docs(
    tags=["connection"],
    summary="Create a new connection invitation",
)
@querystring_schema(CreateInvitationQueryStringSchema())
@request_schema(CreateInvitationRequestSchema())
@response_schema(InvitationResultSchema(), 200, description="")
async def connections_create_invitation(request: web.BaseRequest):
    """
    Request handler for creating a new connection invitation.

    Args:
        request: aiohttp request object

    Returns:
        The connection invitation details

    """
    context: AdminRequestContext = request["context"]
    auto_accept = json.loads(request.query.get("auto_accept", "null"))
    alias = request.query.get("alias")
    public = json.loads(request.query.get("public", "false"))
    multi_use = json.loads(request.query.get("multi_use", "false"))
    body = await request.json() if request.body_exists else {}
    my_label = body.get("my_label")
    recipient_keys = body.get("recipient_keys")
    service_endpoint = body.get("service_endpoint")
    routing_keys = body.get("routing_keys")
    metadata = body.get("metadata")
    mediation_id = body.get("mediation_id")

    if public and not context.settings.get("public_invites"):
        raise web.HTTPForbidden(
            reason="Configuration does not include public invitations"
        )
    session = await context.session()
    base_url = session.settings.get("invite_base_url")

    connection_mgr = ConnectionManager(session)
    try:
        (connection, invitation) = await connection_mgr.create_invitation(
            my_label=my_label,
            auto_accept=auto_accept,
            public=public,
            multi_use=multi_use,
            alias=alias,
            recipient_keys=recipient_keys,
            my_endpoint=service_endpoint,
            routing_keys=routing_keys,
            metadata=metadata,
            mediation_id=mediation_id,
        )

        result = {
            "connection_id": connection and connection.connection_id,
            "invitation": invitation.serialize(),
            "invitation_url": invitation.to_url(base_url),
        }
    except (ConnectionManagerError, StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if connection and connection.alias:
        result["alias"] = connection.alias

    return web.json_response(result)


@docs(
    tags=["connection"],
    summary="Receive a new connection invitation",
)
@querystring_schema(ReceiveInvitationQueryStringSchema())
@request_schema(ReceiveInvitationRequestSchema())
@response_schema(ConnRecordSchema(), 200, description="")
async def connections_receive_invitation(request: web.BaseRequest):
    """
    Request handler for receiving a new connection invitation.

    Args:
        request: aiohttp request object

    Returns:
        The resulting connection record details

    """
    context: AdminRequestContext = request["context"]
    if context.settings.get("admin.no_receive_invites"):
        raise web.HTTPForbidden(
            reason="Configuration does not allow receipt of invitations"
        )
    session = await context.session()
    connection_mgr = ConnectionManager(session)
    invitation_json = await request.json()

    try:
        invitation = ConnectionInvitation.deserialize(invitation_json)
        auto_accept = json.loads(request.query.get("auto_accept", "null"))
        alias = request.query.get("alias")
        mediation_id = request.query.get("mediation_id")
        connection = await connection_mgr.receive_invitation(
            invitation, auto_accept=auto_accept, alias=alias, mediation_id=mediation_id
        )
        result = connection.serialize()
    except (ConnectionManagerError, StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(
    tags=["connection"],
    summary="Accept a stored connection invitation",
)
@match_info_schema(ConnIdMatchInfoSchema())
@querystring_schema(AcceptInvitationQueryStringSchema())
@response_schema(ConnRecordSchema(), 200, description="")
async def connections_accept_invitation(request: web.BaseRequest):
    """
    Request handler for accepting a stored connection invitation.

    Args:
        request: aiohttp request object

    Returns:
        The resulting connection record details

    """
    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]
    connection_id = request.match_info["conn_id"]
    session = await context.session()

    try:
        connection = await ConnRecord.retrieve_by_id(session, connection_id)
        connection_mgr = ConnectionManager(session)
        my_label = request.query.get("my_label")
        my_endpoint = request.query.get("my_endpoint")
        mediation_id = request.query.get("mediation_id")

        try:
            request = await connection_mgr.create_request(
                connection, my_label, my_endpoint, mediation_id=mediation_id
            )
        except StorageError as err:
            # Handle storage errors (including not found errors) from
            # create_request separately as these errors represent a bad request
            # rather than a bad url
            raise web.HTTPBadRequest(reason=err.roll_up) from err

        result = connection.serialize()
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, WalletError, ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    await outbound_handler(request, connection_id=connection.connection_id)
    return web.json_response(result)


@docs(
    tags=["connection"],
    summary="Accept a stored connection request",
)
@match_info_schema(ConnIdMatchInfoSchema())
@querystring_schema(AcceptRequestQueryStringSchema())
@response_schema(ConnRecordSchema(), 200, description="")
async def connections_accept_request(request: web.BaseRequest):
    """
    Request handler for accepting a stored connection request.

    Args:
        request: aiohttp request object

    Returns:
        The resulting connection record details

    """
    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]
    connection_id = request.match_info["conn_id"]
    session = await context.session()

    try:
        connection = await ConnRecord.retrieve_by_id(session, connection_id)
        connection_mgr = ConnectionManager(session)
        my_endpoint = request.query.get("my_endpoint") or None
        response = await connection_mgr.create_response(connection, my_endpoint)
        result = connection.serialize()
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, WalletError, ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    await outbound_handler(response, connection_id=connection.connection_id)
    return web.json_response(result)


@docs(
    tags=["connection"], summary="Assign another connection as the inbound connection"
)
@match_info_schema(ConnIdRefIdMatchInfoSchema())
@response_schema(ConnectionModuleResponseSchema(), 200, description="")
async def connections_establish_inbound(request: web.BaseRequest):
    """
    Request handler for setting the inbound connection on a connection record.

    Args:
        request: aiohttp request object
    """
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    outbound_handler = request["outbound_message_router"]
    inbound_connection_id = request.match_info["ref_id"]
    session = await context.session()

    try:
        connection = await ConnRecord.retrieve_by_id(session, connection_id)
        connection_mgr = ConnectionManager(session)
        await connection_mgr.establish_inbound(
            connection, inbound_connection_id, outbound_handler
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, WalletError, ConnectionManagerError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({})


@docs(tags=["connection"], summary="Remove an existing connection record")
@match_info_schema(ConnIdMatchInfoSchema())
@response_schema(ConnectionModuleResponseSchema, 200, description="")
async def connections_remove(request: web.BaseRequest):
    """
    Request handler for removing a connection record.

    Args:
        request: aiohttp request object
    """
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    session = await context.session()

    try:
        connection = await ConnRecord.retrieve_by_id(session, connection_id)
        await connection.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({})


@docs(tags=["connection"], summary="Create a new static connection")
@request_schema(ConnectionStaticRequestSchema())
@response_schema(ConnectionStaticResultSchema(), 200, description="")
async def connections_create_static(request: web.BaseRequest):
    """
    Request handler for creating a new static connection.

    Args:
        request: aiohttp request object

    Returns:
        The new connection record

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()
    session = await context.session()

    connection_mgr = ConnectionManager(session)
    try:
        (
            my_info,
            their_info,
            connection,
        ) = await connection_mgr.create_static_connection(
            my_seed=body.get("my_seed") or None,
            my_did=body.get("my_did") or None,
            their_seed=body.get("their_seed") or None,
            their_did=body.get("their_did") or None,
            their_verkey=body.get("their_verkey") or None,
            their_endpoint=body.get("their_endpoint") or None,
            their_label=body.get("their_label") or None,
            alias=body.get("alias") or None,
        )
        response = {
            "my_did": my_info.did,
            "my_verkey": my_info.verkey,
            "my_endpoint": context.settings.get("default_endpoint"),
            "their_did": their_info.did,
            "their_verkey": their_info.verkey,
            "record": connection.serialize(),
        }
    except (WalletError, StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(response)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/connections", connections_list, allow_head=False),
            web.get("/connections/{conn_id}", connections_retrieve, allow_head=False),
            web.get(
                "/connections/{conn_id}/metadata",
                connections_metadata,
                allow_head=False,
            ),
            web.post("/connections/{conn_id}/metadata", connections_metadata_set),
            web.get(
                "/connections/{conn_id}/endpoints",
                connections_endpoints,
                allow_head=False,
            ),
            web.post("/connections/create-static", connections_create_static),
            web.post("/connections/create-invitation", connections_create_invitation),
            web.post("/connections/receive-invitation", connections_receive_invitation),
            web.post(
                "/connections/{conn_id}/accept-invitation",
                connections_accept_invitation,
            ),
            web.post(
                "/connections/{conn_id}/accept-request",
                connections_accept_request,
            ),
            web.post(
                "/connections/{conn_id}/establish-inbound/{ref_id}",
                connections_establish_inbound,
            ),
            web.delete("/connections/{conn_id}", connections_remove),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "connection",
            "description": "Connection management",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
