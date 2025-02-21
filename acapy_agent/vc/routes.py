"""VC-API Routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow.exceptions import ValidationError
from uuid_utils import uuid4

from ..admin.decorators.auth import tenant_authentication
from ..admin.request_context import AdminRequestContext
from ..config.base import InjectionError
from ..resolver.base import ResolverError
from ..storage.error import StorageDuplicateError, StorageError, StorageNotFoundError
from ..storage.vc_holder.base import VCHolder
from ..wallet.base import BaseWallet
from ..wallet.error import WalletError
from .vc_ld.manager import VcLdpManager, VcLdpManagerError
from .vc_ld.models import web_schemas
from .vc_ld.models.credential import VerifiableCredential
from .vc_ld.models.options import LDProofVCOptions
from .vc_ld.models.presentation import VerifiablePresentation


@docs(tags=["vc-api"], summary="List credentials")
@response_schema(web_schemas.ListCredentialsResponse(), 200, description="")
@tenant_authentication
async def list_credentials_route(request: web.BaseRequest):
    """Request handler for issuing a credential.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    holder = context.inject(VCHolder)
    try:
        search = holder.search_credentials()
        records = {
            "results": [
                record.serialize()["cred_value"] for record in await search.fetch()
            ]
        }
        return web.json_response(records, status=200)
    except (StorageError, StorageNotFoundError) as err:
        return web.json_response({"message": err.roll_up}, status=400)


@docs(tags=["vc-api"], summary="Fetch credential by ID")
@response_schema(web_schemas.FetchCredentialResponse(), 200, description="")
@tenant_authentication
async def fetch_credential_route(request: web.BaseRequest):
    """Request handler for issuing a credential.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    holder = context.inject(VCHolder)
    try:
        credential_id = request.match_info["credential_id"].strip('"')
        record = await holder.retrieve_credential_by_id(record_id=credential_id)
        return web.json_response(record.serialize()["cred_value"], status=200)
    except (StorageError, StorageNotFoundError) as err:
        return web.json_response({"message": err.roll_up}, status=400)


@docs(tags=["vc-api"], summary="Issue a credential")
@request_schema(web_schemas.IssueCredentialRequest())
@response_schema(web_schemas.IssueCredentialResponse(), 200, description="")
@tenant_authentication
async def issue_credential_route(request: web.BaseRequest):
    """Request handler for issuing a credential.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    manager = VcLdpManager(context.profile)
    try:
        credential = body["credential"]
        options = {} if "options" not in body else body["options"]

        # We derive the proofType from the issuer DID if not provided in options
        if not options.get("proofType", None):
            issuer = credential["issuer"]
            did = issuer if isinstance(issuer, str) else issuer["id"]
            async with context.session() as session:
                wallet: BaseWallet | None = session.inject_or(BaseWallet)
                info = await wallet.get_local_did(did)
                key_type = info.key_type.key_type

            if key_type == "ed25519":
                options["proofType"] = "Ed25519Signature2020"
            elif key_type == "bls12381g2":
                options["proofType"] = "BbsBlsSignature2020"
            elif key_type == "p256":
                options["proofType"] = "EcdsaSecp256r1Signature2019"

        credential = VerifiableCredential.deserialize(credential)
        options = LDProofVCOptions.deserialize(options)

        vc = await manager.issue(credential, options)
        response = {"verifiableCredential": vc.serialize()}
        return web.json_response(response, status=201)
    except (ValidationError, VcLdpManagerError, WalletError, InjectionError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Verify a credential")
@request_schema(web_schemas.VerifyCredentialRequest())
@response_schema(web_schemas.VerifyCredentialResponse(), 200, description="")
@tenant_authentication
async def verify_credential_route(request: web.BaseRequest):
    """Request handler for verifying a credential.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    manager = VcLdpManager(context.profile)
    try:
        vc = VerifiableCredential.deserialize(body["verifiableCredential"])
        result = await manager.verify_credential(vc)
        result = result.serialize()
        return web.json_response(result)
    except (
        ValidationError,
        VcLdpManagerError,
        ResolverError,
        ValueError,
        WalletError,
        InjectionError,
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Store a credential")
@request_schema(web_schemas.StoreCredentialRequest())
@response_schema(web_schemas.StoreCredentialResponse(), 200, description="")
@tenant_authentication
async def store_credential_route(request: web.BaseRequest):
    """Request handler for storing a credential.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    manager = VcLdpManager(context.profile)

    try:
        vc = body["verifiableCredential"]
        cred_id = vc["id"] if "id" in vc else f"urn:uuid:{str(uuid4())}"
        options = {} if "options" not in body else body["options"]

        vc = VerifiableCredential.deserialize(vc)
        options = LDProofVCOptions.deserialize(options)

        await manager.verify_credential(vc)
        await manager.store_credential(vc, cred_id)

        return web.json_response({"credentialId": cred_id}, status=200)

    except (
        ValidationError,
        VcLdpManagerError,
        WalletError,
        InjectionError,
        StorageDuplicateError,
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Prove a presentation")
@request_schema(web_schemas.ProvePresentationRequest())
@response_schema(web_schemas.ProvePresentationResponse(), 200, description="")
@tenant_authentication
async def prove_presentation_route(request: web.BaseRequest):
    """Request handler for proving a presentation.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    manager = VcLdpManager(context.profile)
    body = await request.json()
    try:
        presentation = body["presentation"]
        options = {} if "options" not in body else body["options"]

        # Default proof Type
        if not options.get("proofType", None):
            options["proofType"] = "Ed25519Signature2020"

        presentation = VerifiablePresentation.deserialize(presentation)
        options = LDProofVCOptions.deserialize(options)
        vp = await manager.prove(presentation, options)
        return web.json_response({"verifiablePresentation": vp.serialize()}, status=201)

    except (ValidationError, VcLdpManagerError, WalletError, InjectionError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Verify a Presentation")
@request_schema(web_schemas.VerifyPresentationRequest())
@response_schema(web_schemas.VerifyPresentationResponse(), 200, description="")
@tenant_authentication
async def verify_presentation_route(request: web.BaseRequest):
    """Request handler for verifying a presentation.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    manager = VcLdpManager(context.profile)
    body = await request.json()
    try:
        vp = VerifiablePresentation.deserialize(body["verifiablePresentation"])
        options = {} if "options" not in body else body["options"]
        options = LDProofVCOptions.deserialize(options)
        verified = await manager.verify_presentation(vp, options)
        return web.json_response(verified.serialize(), status=200)
    except (
        ValidationError,
        WalletError,
        InjectionError,
        VcLdpManagerError,
        ResolverError,
        ValueError,
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/vc/credentials", list_credentials_route, allow_head=False),
            web.get(
                "/vc/credentials/{credential_id}",
                fetch_credential_route,
                allow_head=False,
            ),
            web.post("/vc/credentials/issue", issue_credential_route),
            web.post("/vc/credentials/store", store_credential_route),
            web.post("/vc/credentials/verify", verify_credential_route),
            web.post("/vc/presentations/prove", prove_presentation_route),
            web.post("/vc/presentations/verify", verify_presentation_route),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "vc-api",
            "description": "Endpoints for managing w3c credentials and presentations",
            "externalDocs": {
                "description": "Specification",
                "url": "https://w3c-ccg.github.io/vc-api/",
            },
        }
    )
