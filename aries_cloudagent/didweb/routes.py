"""
DID web admin routes and public endpoint.

"""

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    # querystring_schema,
    request_schema,
    response_schema,
)

from marshmallow import fields, validate
from ..admin.request_context import AdminRequestContext
from ..messaging.models.openapi import OpenAPISchema
from pydid.common import DID_PATTERN
from .base import DIDWeb


class W3cDIDDoc(validate.Regexp):
    """Validate value against w3c DID document."""

    EXAMPLE = "*"
    PATTERN = DID_PATTERN

    def __init__(self):
        """Initializer."""

        super().__init__(
            W3cDIDDoc.PATTERN,
            error="Value {input} is not a w3c decentralized identifier (DID) doc.",
        )


_W3cDIDDoc = {"validate": W3cDIDDoc(), "example": W3cDIDDoc.EXAMPLE}


class DIDDocSchema(OpenAPISchema):
    """Result schema for did document query."""

    did_doc = fields.Str(
        description="decentralize identifier(DID) document", required=True
    )


class DIDDocOptionsSchema(OpenAPISchema):
    """Todo."""

    verification_methods = fields.List(
        fields.Dict(
            did=fields.Str(description="did", required=False),
            verification_relationships=fields.List(
                fields.Str(description="verification relationships", required=False),
                description="List of verification relationships"
            )
        ),
        required=False,
        description="List of verification methods",
    )

    services = fields.List(
        fields.Dict(description="service block", required=False),
        description="List of service blocks", required=False
    )


class W3cDID(validate.Regexp):
    """Validate value against w3c DID."""

    EXAMPLE = "did:ted:WgWxqztrNooG92RXvxSTWv"
    PATTERN = DID_PATTERN

    def __init__(self):
        """Initializer."""

        super().__init__(
            W3cDID.PATTERN,
            error="Value {input} is not a w3c decentralized identifier (DID)",
        )


_W3cDID = {"validate": W3cDID(), "example": W3cDID.EXAMPLE}


class DIDMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking DID."""

    did = fields.Str(
        description="decentralize identifier(DID)", required=True, **_W3cDID
    )


async def did_document(request: web.BaseRequest):
    """Retrieve a did document."""
    context: AdminRequestContext = request["context"]
    session = await context.session()
    did_web = DIDWeb(session)
    # did_web = session.inject(DIDWeb)
    did_document = await did_web.retrieve()
    # except DIDNotFound as err:
    #     raise web.HTTPNotFound(reason=err.roll_up) from err
    # except DIDMethodNotSupported as err:
    #     raise web.HTTPNotImplemented(reason=err.roll_up) from err
    # except ResolverError as err:
    #     raise web.HTTPInternalServerError(reason=err.roll_up) from err
    return web.json_response(did_document)


@docs(tags=["didweb"], summary="Retrieve DID document")
@response_schema(DIDDocSchema(), 200)
async def read_did_document(request: web.BaseRequest):
    """Retrieve a did document."""

    context: AdminRequestContext = request["context"]
    session = await context.session()
    did_web = DIDWeb(session)

    did_document = await did_web.retrieve()
    # except DIDNotFound as err:
    #     raise web.HTTPNotFound(reason=err.roll_up) from err
    # except DIDMethodNotSupported as err:
    #     raise web.HTTPNotImplemented(reason=err.roll_up) from err
    # except ResolverError as err:
    #     raise web.HTTPInternalServerError(reason=err.roll_up) from err
    if not did_document:
        return web.HTTPNotFound()
    else:
        return web.json_response(did_document)


@docs(tags=["didweb"], summary="Create DID document")
@request_schema(DIDDocSchema())
@response_schema(DIDDocSchema(), 200, description="")
async def create_did_document(request: web.BaseRequest):
    """Create a did document."""
    context: AdminRequestContext = request["context"]
    session = await context.session()
    did_web = DIDWeb(session)
    # did_web = session.inject(DIDWeb)
    did_document = await did_web.create()
    # except DIDNotFound as err:
    #     raise web.HTTPNotFound(reason=err.roll_up) from err
    # except DIDMethodNotSupported as err:
    #     raise web.HTTPNotImplemented(reason=err.roll_up) from err
    # except ResolverError as err:
    #     raise web.HTTPInternalServerError(reason=err.roll_up) from err
    return web.json_response(did_document)


@docs(tags=["didweb"], summary="Create DID document")
@match_info_schema(DIDMatchInfoSchema())
@request_schema(DIDDocOptionsSchema())
@response_schema(DIDDocSchema(), 200, description="")
async def create_did_document_from_wallet(request: web.BaseRequest):
    """Create a did document."""
    did = request.match_info["did"]
    context: AdminRequestContext = request["context"]
    session = await context.session()
    did_web = DIDWeb(session)
    options = await request.json()
    did_document = await did_web.create_from_wallet(did, options)
    return web.json_response(did_document)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/.well-known/did.json", did_document, allow_head=False),
            web.get("/didweb/read", read_did_document, allow_head=False),
            web.post("/didweb/create-raw", create_did_document),
            web.post("/didweb/create-from-wallet/{did}", create_did_document_from_wallet)
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "didweb",
            "description": "did web interface.",
            "externalDocs": {
                "description": "Specification",
                "url": "https://w3c-ccg.github.io/did-method-web"
            },
        }
    )
