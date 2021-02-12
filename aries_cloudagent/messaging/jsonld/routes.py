"""jsonld admin routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema

from marshmallow import Schema, fields

from ...admin.request_context import AdminRequestContext

from ..models.openapi import OpenAPISchema

from .credential import sign_credential, verify_credential
from ...storage.error import StorageError, StorageNotFoundError
from ...messaging.models.base import BaseModelError
from ...wallet.error import WalletError
from ...resolver.did import DID


class SignRequestSchema(OpenAPISchema):
    """Request schema for signing a jsonld doc."""

    verkey = fields.Str(required=True, description="verkey to use for signing")
    doc_schema = Schema.from_dict(
        {
            "credential": fields.Dict(required=False),
            "options": fields.Dict(required=False),
        }
    )
    doc = fields.Nested(doc_schema(), required=True, description="JSON-LD Doc to sign")


class SignResponseSchema(OpenAPISchema):
    """Response schema for a signed jsonld doc."""

    signed_doc = fields.Dict(required=True)


@docs(tags=["jsonld"], summary="Sign a JSON-LD structure and return it")
@request_schema(SignRequestSchema())
@response_schema(SignResponseSchema(), 200, description="")
async def sign(request: web.BaseRequest):
    """
    Request handler for signing a jsonld doc.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    session = await context.session()
    response = {}
    body = await request.json()
    verkey = body.get("verkey")
    doc = body.get("doc")
    credential = doc.get("credential")
    signature_options = doc.get("options")
    try:
        document_with_proof = await sign_credential(
            credential, signature_options, verkey, session
        )
        response["signed_doc"] = document_with_proof
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, WalletError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response(response)


class VerifyRequestSchema(OpenAPISchema):
    """Request schema for signing a jsonld doc."""

    verkey = fields.Str(required=False, description="verkey to use for doc verification")
    doc = fields.Dict(required=True, description="JSON-LD Doc to verify")


class VerifyResponseSchema(OpenAPISchema):
    """Response schema for verification result."""

    valid = fields.Bool(required=True)


@docs(tags=["jsonld"], summary="Verify a JSON-LD structure.")
@request_schema(VerifyRequestSchema())
@response_schema(VerifyResponseSchema(), 200, description="")
async def verify(request: web.BaseRequest):
    """
    Request handler for signing a jsonld doc.

    Args:
        request: aiohttp request object

    """
    response = {"valid": False}
    context: AdminRequestContext = request["context"]
    session = await context.session()
    body = await request.json()
    verkey = body.get("verkey")
    doc = body.get("doc")
    try:
        if not verkey and "issuer" in doc.keys():
            verkey = DID(doc["issuer"]).method_specific_id()
        valid = await verify_credential(doc, verkey, session)
        response["valid"] = valid
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, WalletError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response(response)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes([web.post("/jsonld/sign", sign), web.post("/jsonld/verify", verify)])


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "json-ld sign/verify",
            "description": "sign and verify json-ld data.",
            "externalDocs": {"description": "Specification"},  # , "url": SPEC_URI},
        }
    )
