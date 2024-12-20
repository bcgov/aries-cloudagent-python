"""Trust ping admin routes."""

from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, request_schema, response_schema
from marshmallow import fields
from didcomm_messaging import DIDCommMessaging, RoutingService
from didcomm_messaging.resolver import DIDResolver as DMPResolver

from ....admin.decorators.auth import tenant_authentication
from ....admin.request_context import AdminRequestContext
from ....connections.models.conn_record import ConnRecord
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import UUID4_EXAMPLE
from ....storage.error import StorageNotFoundError
from .message_types import SPEC_URI


class BaseDIDCommV2Schema(OpenAPISchema):
    """Request schema for performing a ping."""

    to_did = fields.Str(
        required=True,
        allow_none=False,
        metadata={"description": "Comment for the ping message"},
    )


class PingRequestSchema(BaseDIDCommV2Schema):
    """Request schema for performing a ping."""

    response_requested = fields.Bool(
        required=False,
        allow_none=True,
        metadata={"description": "Comment for the ping message"},
    )


class PingRequestResponseSchema(OpenAPISchema):
    """Request schema for performing a ping."""

    thread_id = fields.Str(
        required=False, metadata={"description": "Thread ID of the ping message"}
    )


class PingConnIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking connection id."""

    conn_id = fields.Str(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )

from ....wallet.base import BaseWallet
from ....wallet.did_info import DIDInfo
from ....wallet.did_method import KEY, PEER2, PEER4, SOV, DIDMethod, DIDMethods, HolderDefinedDid
from ....wallet.did_posture import DIDPosture
from ....wallet.error import WalletError, WalletNotFoundError
from ....messaging.v2_agent_message import V2AgentMessage
from ....connections.models.connection_target import ConnectionTarget
from didcomm_messaging import DIDCommMessaging, RoutingService
def format_did_info(info: DIDInfo):
    """Serialize a DIDInfo object."""
    if info:
        return {
            "did": info.did,
            "verkey": info.verkey,
            "posture": DIDPosture.get(info.metadata).moniker,
            "key_type": info.key_type.key_type,
            "method": info.method.method_name,
            "metadata": info.metadata,
        }

async def get_mydid(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    #filter_did = request.query.get("did")
    #filter_verkey = request.query.get("verkey")
    filter_posture = DIDPosture.get(request.query.get("posture"))
    results = []
    async with context.session() as session:
        did_methods: DIDMethods = session.inject(DIDMethods)
        filter_method: DIDMethod | None = did_methods.from_method(
            request.query.get("method") or "did:peer:2"
        )
        #key_types = session.inject(KeyTypes)
        #filter_key_type = key_types.from_key_type(request.query.get("key_type", ""))
        wallet: BaseWallet | None = session.inject_or(BaseWallet)
        if not wallet:
            raise web.HTTPForbidden(reason="No wallet available")
        else:
            dids = await wallet.get_local_dids()
            results = [
                format_did_info(info)
                for info in dids
                if (
                    filter_posture is None
                    or DIDPosture.get(info.metadata) is DIDPosture.WALLET_ONLY
                )
                and (not filter_method or info.method == filter_method)
                #and (not filter_key_type or info.key_type == filter_key_type)
            ]

    results.sort(key=lambda info: (DIDPosture.get(info["posture"]).ordinal, info["did"]))
    our_did = results[0]["did"]
    return our_did

async def get_target(request: web.BaseRequest, to_did: str, from_did: str):
    context: AdminRequestContext = request["context"]

    try:
        async with context.profile.session() as session:
            resolver = session.inject(DMPResolver)
            did_doc = await resolver.resolve(to_did)
    except Exception as err:
        raise web.HTTPNotFound(reason=str(err)) from err

    async with context.session() as session:
        ctx = session
        messaging = ctx.inject(DIDCommMessaging)
        routing_service = ctx.inject(RoutingService)
        frm = to_did
        services = await routing_service._resolve_services(messaging.resolver, frm)
        chain = [
            {
                "did": frm,
                "service": services,
            }
        ]

        # Loop through service DIDs until we run out of DIDs to forward to
        to_target = services[0].service_endpoint.uri
        found_forwardable_service = await routing_service.is_forwardable_service(
            messaging.resolver, services[0]
        )
        while found_forwardable_service:
            services = await routing_service._resolve_services(messaging.resolver, to_target)
            if services:
                chain.append(
                    {
                        "did": to_target,
                        "service": services,
                    }
                )
                to_target = services[0].service_endpoint.uri
            found_forwardable_service = (
                await routing_service.is_forwardable_service(messaging.resolver, services[0])
                if services
                else False
            )
        reply_destination = [
            ConnectionTarget(
                did=f"{to_did}#key-1",
                endpoint=service.service_endpoint.uri,
                recipient_keys=[f"{to_did}#key-1"],
                sender_key=from_did + "#key-1",
            )
            for service in chain[-1]["service"]
        ]
    return reply_destination


class DiscoverFeaturesQuerySchema(BaseDIDCommV2Schema):
    """Request schema for performing a ping."""

    queries = fields.Bool(
        required=False,
        allow_none=True,
        metadata={"description": "Comment for the ping message"},
    )


@docs(tags=["discoveryv2", "didcommv2"], summary="Request the list of supported features")
@request_schema(DiscoverFeaturesQuerySchema())
@response_schema(PingRequestResponseSchema(), 200, description="")
@tenant_authentication
async def discover_features_query(request: web.BaseRequest):
    """Request handler for sending a trust ping to a connection.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]
    body = await request.json()
    to_did = body.get("to_did")

    our_did = await get_mydid(request)
    their_did = to_did
    reply_destination = await get_target(request, to_did, our_did)
    msg = V2AgentMessage(
        message={
            "type": "https://didcomm.org/discover-features/2.0/queries",
            "body": {
                "queries": [
                    {
                        "feature-type": "protocol",
                        "match": "https://didcomm.org/*",
                    },
                    {
                        "feature-type": "goal-code",
                        "match": "org.didcomm.*",
                    },
                ]
            },
            "to": [their_did],
            "from": our_did,
        }
    )
    await outbound_handler(msg, target_list=reply_destination)
    return web.json_response(msg.message)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes([web.post("/discover-features/send-query", discover_features_query)])


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "discoveryv2",
            "description": "Feature Discovery to Contact",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "didcommv2",
            "description": "DIDComm V2 based protocols for Interop-a-thon",
            "externalDocs": {"description": "Specification", "url": "https://didcomm.org"},
        }
    )
