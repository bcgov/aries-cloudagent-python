"""Credential exchange admin routes."""

import logging
from json.decoder import JSONDecodeError
from typing import Mapping, Optional

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import ValidationError, fields, validate, validates_schema

from ....admin.decorators.auth import tenant_authentication
from ....admin.request_context import AdminRequestContext
from ....anoncreds.holder import AnonCredsHolderError
from ....anoncreds.issuer import AnonCredsIssuerError
from ....connections.models.conn_record import ConnRecord
from ....core.profile import Profile
from ....indy.holder import IndyHolderError
from ....indy.issuer import IndyIssuerError
from ....ledger.error import LedgerError
from ....messaging.decorators.attach_decorator import AttachDecorator
from ....messaging.models.base import BaseModelError
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.models.paginated_query import (
    PaginatedQuerySchema,
    get_paginated_query_params,
)
from ....messaging.valid import (
    ANONCREDS_CRED_DEF_ID_EXAMPLE,
    ANONCREDS_DID_EXAMPLE,
    ANONCREDS_SCHEMA_ID_EXAMPLE,
    INDY_CRED_DEF_ID_EXAMPLE,
    INDY_CRED_DEF_ID_VALIDATE,
    INDY_DID_EXAMPLE,
    INDY_DID_VALIDATE,
    INDY_SCHEMA_ID_EXAMPLE,
    INDY_SCHEMA_ID_VALIDATE,
    MAJOR_MINOR_VERSION_EXAMPLE,
    MAJOR_MINOR_VERSION_VALIDATE,
    UUID4_EXAMPLE,
    UUID4_VALIDATE,
)
from ....storage.error import StorageError, StorageNotFoundError
from ....utils.tracing import AdminAPIMessageTracingSchema, get_timer, trace_event
from ....vc.ld_proofs.error import LinkedDataProofException
from ....wallet.util import default_did_from_verkey
from ...out_of_band.v1_0.models.oob_record import OobRecord
from . import problem_report_for_record, report_problem
from .formats.handler import V20CredFormatError
from .formats.ld_proof.models.cred_detail import LDProofVCDetailSchema
from .manager import V20CredManager, V20CredManagerError
from .message_types import ATTACHMENT_FORMAT, CRED_20_PROPOSAL, SPEC_URI
from .messages.cred_format import V20CredFormat
from .messages.cred_problem_report import ProblemReportReason
from .messages.cred_proposal import V20CredProposal
from .messages.inner.cred_preview import V20CredPreview, V20CredPreviewSchema
from .models.cred_ex_record import V20CredExRecord, V20CredExRecordSchema
from .models.detail.indy import V20CredExRecordIndySchema
from .models.detail.ld_proof import V20CredExRecordLDProofSchema

LOGGER = logging.getLogger(__name__)


class V20IssueCredentialModuleResponseSchema(OpenAPISchema):
    """Response schema for v2.0 Issue Credential Module."""


class V20CredExRecordListQueryStringSchema(PaginatedQuerySchema):
    """Parameters and validators for credential exchange record list query."""

    connection_id = fields.Str(
        required=False,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )
    thread_id = fields.Str(
        required=False,
        metadata={"description": "Thread identifier", "example": UUID4_EXAMPLE},
    )
    role = fields.Str(
        required=False,
        validate=validate.OneOf(
            [
                getattr(V20CredExRecord, m)
                for m in vars(V20CredExRecord)
                if m.startswith("ROLE_")
            ]
        ),
        metadata={"description": "Role assigned in credential exchange"},
    )
    state = fields.Str(
        required=False,
        validate=validate.OneOf(
            [
                getattr(V20CredExRecord, m)
                for m in vars(V20CredExRecord)
                if m.startswith("STATE_")
            ]
        ),
        metadata={"description": "Credential exchange state"},
    )


class V20CredExRecordDetailSchema(OpenAPISchema):
    """Credential exchange record and any per-format details."""

    cred_ex_record = fields.Nested(
        V20CredExRecordSchema,
        required=False,
        metadata={"description": "Credential exchange record"},
    )

    indy = fields.Nested(V20CredExRecordIndySchema, required=False)
    ld_proof = fields.Nested(V20CredExRecordLDProofSchema, required=False)
    vc_di = fields.Nested(V20CredExRecordSchema, required=False)


class V20CredExRecordListResultSchema(OpenAPISchema):
    """Result schema for credential exchange record list query."""

    results = fields.List(
        fields.Nested(V20CredExRecordDetailSchema),
        metadata={
            "description": (
                "Credential exchange records and corresponding detail records"
            )
        },
    )


class V20CredStoreRequestSchema(OpenAPISchema):
    """Request schema for sending a credential store admin message."""

    credential_id = fields.Str(required=False)


class V20CredFilterAnoncredsSchema(OpenAPISchema):
    """Anoncreds credential filtration criteria."""

    schema_issuer_id = fields.Str(
        required=False,
        metadata={
            "description": "Schema issuer ID",
            "example": ANONCREDS_DID_EXAMPLE,
        },
    )
    schema_name = fields.Str(
        required=False,
        metadata={"description": "Schema name", "example": "preferences"},
    )
    schema_version = fields.Str(
        required=False,
        metadata={
            "description": "Schema version",
            "example": MAJOR_MINOR_VERSION_EXAMPLE,
        },
    )
    schema_id = fields.Str(
        required=False,
        metadata={
            "description": "Schema identifier",
            "example": ANONCREDS_SCHEMA_ID_EXAMPLE,
        },
    )
    issuer_id = fields.Str(
        required=False,
        metadata={
            "description": "Credential issuer ID",
            "example": ANONCREDS_DID_EXAMPLE,
        },
    )
    cred_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Credential definition identifier",
            "example": ANONCREDS_CRED_DEF_ID_EXAMPLE,
        },
    )


class V20CredFilterIndySchema(OpenAPISchema):
    """Indy credential filtration criteria."""

    cred_def_id = fields.Str(
        required=False,
        validate=INDY_CRED_DEF_ID_VALIDATE,
        metadata={
            "description": "Credential definition identifier",
            "example": INDY_CRED_DEF_ID_EXAMPLE,
        },
    )
    schema_id = fields.Str(
        required=False,
        validate=INDY_SCHEMA_ID_VALIDATE,
        metadata={
            "description": "Schema identifier",
            "example": INDY_SCHEMA_ID_EXAMPLE,
        },
    )
    schema_issuer_did = fields.Str(
        required=False,
        validate=INDY_DID_VALIDATE,
        metadata={"description": "Schema issuer DID", "example": INDY_DID_EXAMPLE},
    )
    schema_name = fields.Str(
        required=False,
        metadata={"description": "Schema name", "example": "preferences"},
    )
    schema_version = fields.Str(
        required=False,
        validate=MAJOR_MINOR_VERSION_VALIDATE,
        metadata={
            "description": "Schema version",
            "example": MAJOR_MINOR_VERSION_EXAMPLE,
        },
    )
    issuer_did = fields.Str(
        required=False,
        validate=INDY_DID_VALIDATE,
        metadata={"description": "Credential issuer DID", "example": INDY_DID_EXAMPLE},
    )


class V20CredFilterVCDISchema(OpenAPISchema):
    """VCDI credential filtration criteria."""

    cred_def_id = fields.Str(
        required=False,
        validate=INDY_CRED_DEF_ID_VALIDATE,
        metadata={
            "description": "Credential definition identifier",
            "example": INDY_CRED_DEF_ID_EXAMPLE,
        },
    )
    schema_id = fields.Str(
        required=False,
        validate=INDY_SCHEMA_ID_VALIDATE,
        metadata={
            "description": "Schema identifier",
            "example": INDY_SCHEMA_ID_EXAMPLE,
        },
    )
    schema_issuer_did = fields.Str(
        required=False,
        validate=INDY_DID_VALIDATE,
        metadata={"description": "Schema issuer DID", "example": INDY_DID_EXAMPLE},
    )
    schema_name = fields.Str(
        required=False,
        metadata={"description": "Schema name", "example": "preferences"},
    )
    schema_version = fields.Str(
        required=False,
        validate=MAJOR_MINOR_VERSION_VALIDATE,
        metadata={
            "description": "Schema version",
            "example": MAJOR_MINOR_VERSION_EXAMPLE,
        },
    )
    issuer_did = fields.Str(
        required=False,
        validate=INDY_DID_VALIDATE,
        metadata={"description": "Credential issuer DID", "example": INDY_DID_EXAMPLE},
    )


class V20CredFilterSchema(OpenAPISchema):
    """Credential filtration criteria."""

    anoncreds = fields.Nested(
        V20CredFilterAnoncredsSchema,
        required=False,
        metadata={"description": "Credential filter for anoncreds"},
    )
    indy = fields.Nested(
        V20CredFilterIndySchema,
        required=False,
        metadata={"description": "Credential filter for indy"},
    )
    ld_proof = fields.Nested(
        LDProofVCDetailSchema,
        required=False,
        metadata={"description": "Credential filter for linked data proof"},
    )
    vc_di = fields.Nested(
        V20CredFilterVCDISchema,
        required=False,
        metadata={"description": "Credential filter for vc_di"},
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate schema fields.

        Data must have indy, ld_proof, vc_di, or all.

        Args:
            data: The data to validate
            kwargs: Additional keyword arguments

        Raises:
            ValidationError: if data has neither indy nor ld_proof

        """
        if not any(f.api in data for f in V20CredFormat.Format):
            raise ValidationError(
                "V20CredFilterSchema requires indy, ld_proof, vc_di or all"
            )


class V20IssueCredSchemaCore(AdminAPIMessageTracingSchema):
    """Filter, auto-remove, comment, trace."""

    filter_ = fields.Nested(
        V20CredFilterSchema,
        required=True,
        data_key="filter",
        metadata={"description": "Credential specification criteria by format"},
    )
    auto_remove = fields.Bool(
        required=False,
        metadata={
            "description": (
                "Whether to remove the credential exchange record on completion"
                " (overrides --preserve-exchange-records configuration setting)"
            )
        },
    )
    comment = fields.Str(
        required=False,
        allow_none=True,
        metadata={"description": "Human-readable comment"},
    )

    credential_preview = fields.Nested(V20CredPreviewSchema, required=False)

    replacement_id = fields.Str(
        required=False,
        allow_none=True,
        metadata={
            "description": "Optional identifier used to manage credential replacement",
            "example": UUID4_EXAMPLE,
        },
    )

    @validates_schema
    def validate(self, data, **kwargs):
        """Make sure preview is present when indy/vc_di format is present."""

        if (
            data.get("filter", {}).get("indy") or data.get("filter", {}).get("vc_di")
        ) and not data.get("credential_preview"):
            raise ValidationError(
                "Credential preview is required if indy or vc_di filter is present"
            )


class V20CredFilterLDProofSchema(OpenAPISchema):
    """Credential filtration criteria."""

    ld_proof = fields.Nested(
        LDProofVCDetailSchema,
        required=True,
        metadata={"description": "Credential filter for linked data proof"},
    )


class V20CredRequestFreeSchema(AdminAPIMessageTracingSchema):
    """Filter, auto-remove, comment, trace."""

    connection_id = fields.Str(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )
    # Request can only start with LD Proof
    filter_ = fields.Nested(
        V20CredFilterLDProofSchema,
        required=True,
        data_key="filter",
        metadata={"description": "Credential specification criteria by format"},
    )
    auto_remove = fields.Bool(
        required=False,
        metadata={
            "description": (
                "Whether to remove the credential exchange record on completion"
                " (overrides --preserve-exchange-records configuration setting)"
            )
        },
    )
    comment = fields.Str(
        required=False,
        allow_none=True,
        metadata={"description": "Human-readable comment"},
    )
    trace = fields.Bool(
        required=False,
        metadata={
            "description": "Whether to trace event (default false)",
            "example": False,
        },
    )
    holder_did = fields.Str(
        required=False,
        allow_none=True,
        metadata={
            "description": "Holder DID to substitute for the credentialSubject.id",
            "example": "did:key:ahsdkjahsdkjhaskjdhakjshdkajhsdkjahs",
        },
    )


class V20CredExFreeSchema(V20IssueCredSchemaCore):
    """Request schema for sending credential admin message."""

    connection_id = fields.Str(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )

    verification_method = fields.Str(
        required=False,
        dump_default=None,
        allow_none=True,
        metadata={"description": "For ld-proofs. Verification method for signing."},
    )


class V20CredBoundOfferRequestSchema(OpenAPISchema):
    """Request schema for sending bound credential offer admin message."""

    filter_ = fields.Nested(
        V20CredFilterSchema,
        required=False,
        data_key="filter",
        metadata={"description": "Credential specification criteria by format"},
    )
    counter_preview = fields.Nested(
        V20CredPreviewSchema,
        required=False,
        metadata={"description": "Optional content for counter-proposal"},
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate schema fields: need both filter and counter_preview or neither."""
        if (
            "filter_" in data
            and ("indy" in data["filter_"] or "ld_proof" in data["filter_"])
        ) ^ ("counter_preview" in data):
            raise ValidationError(
                f"V20CredBoundOfferRequestSchema\n{data}\nrequires "
                "both indy/ld_proof filter and counter_preview or neither"
            )


class V20CredOfferRequestSchema(V20IssueCredSchemaCore):
    """Request schema for sending credential offer admin message."""

    connection_id = fields.Str(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )
    auto_issue = fields.Bool(
        required=False,
        metadata={
            "description": (
                "Whether to respond automatically to credential requests, creating and"
                " issuing requested credentials"
            )
        },
    )


class V20CredOfferConnFreeRequestSchema(V20IssueCredSchemaCore):
    """Request schema for creating credential offer free from connection."""

    auto_issue = fields.Bool(
        required=False,
        metadata={
            "description": (
                "Whether to respond automatically to credential requests, creating and"
                " issuing requested credentials"
            )
        },
    )


class V20CredRequestRequestSchema(OpenAPISchema):
    """Request schema for sending credential request message."""

    holder_did = fields.Str(
        required=False,
        allow_none=True,
        metadata={
            "description": "Holder DID to substitute for the credentialSubject.id",
            "example": "did:key:ahsdkjahsdkjhaskjdhakjshdkajhsdkjahs",
        },
    )
    auto_remove = fields.Bool(
        required=False,
        dump_default=False,
        metadata={
            "description": (
                "Whether to remove the credential exchange record on completion"
                " (overrides --preserve-exchange-records configuration setting)"
            )
        },
    )


class V20CredIssueRequestSchema(OpenAPISchema):
    """Request schema for sending credential issue admin message."""

    comment = fields.Str(
        required=False,
        allow_none=True,
        metadata={"description": "Human-readable comment"},
    )


class V20CredIssueProblemReportRequestSchema(OpenAPISchema):
    """Request schema for sending problem report."""

    description = fields.Str(required=True)


class V20CredIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking credential id."""

    credential_id = fields.Str(
        required=True,
        metadata={"description": "Credential identifier", "example": UUID4_EXAMPLE},
    )


class V20CredExIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking credential exchange id."""

    cred_ex_id = fields.Str(
        required=True,
        validate=UUID4_VALIDATE,
        metadata={
            "description": "Credential exchange identifier",
            "example": UUID4_EXAMPLE,
        },
    )


def _formats_filters(filt_spec: Mapping) -> Mapping:
    """Break out formats and filters for v2.0 cred proposal messages."""

    return (
        {
            "formats": [
                V20CredFormat(
                    attach_id=fmt_api,
                    format_=ATTACHMENT_FORMAT[CRED_20_PROPOSAL][fmt_api],
                )
                for fmt_api in filt_spec
            ],
            "filters_attach": [
                AttachDecorator.data_base64(filt_by_fmt, ident=fmt_api)
                for (fmt_api, filt_by_fmt) in filt_spec.items()
            ],
        }
        if filt_spec
        else {}
    )


async def _get_attached_credentials(
    profile: Profile, cred_ex_record: V20CredExRecord
) -> Mapping:
    """Fetch the detail records attached to a credential exchange."""
    result = {}

    for fmt in V20CredFormat.Format:
        detail_record = await fmt.handler(profile).get_detail_record(
            cred_ex_record.cred_ex_id
        )
        if detail_record:
            result[fmt.api] = detail_record

    return result


def _format_result_with_details(
    cred_ex_record: V20CredExRecord, details: Mapping
) -> Mapping:
    """Get credential exchange result with detail records."""
    result = {"cred_ex_record": cred_ex_record.serialize()}
    for fmt in V20CredFormat.Format:
        ident = fmt.api
        detail_record = details.get(ident)
        result[ident] = detail_record.serialize() if detail_record else None
    return result


@docs(
    tags=["issue-credential v2.0"],
    summary="Fetch all credential exchange records",
)
@querystring_schema(V20CredExRecordListQueryStringSchema)
@response_schema(V20CredExRecordListResultSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_list(request: web.BaseRequest):
    """Request handler for searching credential exchange records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context: AdminRequestContext = request["context"]
    profile = context.profile
    tag_filter = {}
    if "thread_id" in request.query and request.query["thread_id"] != "":
        tag_filter["thread_id"] = request.query["thread_id"]
    post_filter = {
        k: request.query[k]
        for k in ("connection_id", "role", "state")
        if request.query.get(k, "") != ""
    }

    limit, offset, order_by, descending = get_paginated_query_params(request)

    try:
        async with profile.session() as session:
            cred_ex_records = await V20CredExRecord.query(
                session=session,
                tag_filter=tag_filter,
                limit=limit,
                offset=offset,
                order_by=order_by,
                descending=descending,
                post_filter_positive=post_filter,
            )

        results = []
        for cxr in cred_ex_records:
            details = await _get_attached_credentials(profile, cxr)
            result = _format_result_with_details(cxr, details)
            results.append(result)

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(
    tags=["issue-credential v2.0"],
    summary="Fetch a single credential exchange record",
)
@match_info_schema(V20CredExIdMatchInfoSchema())
@response_schema(V20CredExRecordDetailSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_retrieve(request: web.BaseRequest):
    """Request handler for fetching single credential exchange record.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    cred_ex_id = request.match_info["cred_ex_id"]
    cred_ex_record = None
    try:
        async with profile.session() as session:
            cred_ex_record = await V20CredExRecord.retrieve_by_id(session, cred_ex_id)

        details = await _get_attached_credentials(profile, cred_ex_record)
        result = _format_result_with_details(cred_ex_record, details)
    except StorageNotFoundError as err:
        # no such cred ex record: not protocol error, user fat-fingered id
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, StorageError) as err:
        # present but broken or hopeless: protocol error
        await report_problem(
            err,
            ProblemReportReason.ISSUANCE_ABANDONED.value,
            web.HTTPBadRequest,
            cred_ex_record,
            outbound_handler,
        )

    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary=(
        "Create a credential record without sending (generally for use with Out-Of-Band)"
    ),
)
@request_schema(V20IssueCredSchemaCore())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_create(request: web.BaseRequest):
    """Request handler for creating a credential from attr values.

    The internal credential record will be created without the credential
    being sent to any connection. This can be used in conjunction with
    the `oob` protocols to bind messages to an out of band message.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    body = await request.json()

    comment = body.get("comment")
    preview_spec = body.get("credential_preview")
    filt_spec = body.get("filter")
    auto_remove = body.get(
        "auto_remove", not profile.settings.get("preserve_exchange_records")
    )
    if not filt_spec:
        raise web.HTTPBadRequest(reason="Missing filter")
    trace_msg = body.get("trace")

    try:
        # Not all formats use credential preview
        cred_preview = V20CredPreview.deserialize(preview_spec) if preview_spec else None
        cred_proposal = V20CredProposal(
            comment=comment,
            credential_preview=cred_preview,
            **_formats_filters(filt_spec),
        )
        cred_proposal.assign_trace_decorator(
            context.settings,
            trace_msg,
        )

        trace_event(
            context.settings,
            cred_proposal,
            outcome="credential_exchange_create.START",
        )

        cred_manager = V20CredManager(context.profile)
        (cred_ex_record, cred_offer_message) = await cred_manager.prepare_send(
            connection_id=None,
            cred_proposal=cred_proposal,
            auto_remove=auto_remove,
        )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    trace_event(
        context.settings,
        cred_offer_message,
        outcome="credential_exchange_create.END",
        perf_counter=r_time,
    )

    return web.json_response(cred_ex_record.serialize())


@docs(
    tags=["issue-credential v2.0"],
    summary="Send holder a credential, automating entire flow",
)
@request_schema(V20CredExFreeSchema())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_send(request: web.BaseRequest):
    """Request handler for sending credential from issuer to holder from attr values.

    If both issuer and holder are configured for automatic responses, the operation
    ultimately results in credential issue; otherwise, the result waits on the first
    response not automated; the credential exchange record retains state regardless.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    body = await request.json()

    comment = body.get("comment")
    connection_id = body.get("connection_id")
    verification_method = body.get("verification_method")

    filt_spec = body.get("filter")
    if not filt_spec:
        raise web.HTTPBadRequest(reason="Missing filter")
    preview_spec = body.get("credential_preview")
    auto_remove = body.get(
        "auto_remove", not profile.settings.get("preserve_exchange_records")
    )
    replacement_id = body.get("replacement_id")
    trace_msg = body.get("trace")

    conn_record = None
    cred_ex_record = None
    try:
        # Not all formats use credential preview
        cred_preview = V20CredPreview.deserialize(preview_spec) if preview_spec else None
        async with profile.session() as session:
            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
        if not conn_record.is_ready:
            raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

        # TODO: why do we create a proposal and then use that to create an offer.
        # Seems easier to just pass the proposal data to the format specific handler
        cred_proposal = V20CredProposal(
            comment=comment,
            credential_preview=cred_preview,
            **_formats_filters(filt_spec),
        )
        cred_proposal.assign_trace_decorator(
            context.settings,
            trace_msg,
        )

        trace_event(
            context.settings,
            cred_proposal,
            outcome="credential_exchange_send.START",
        )

        cred_manager = V20CredManager(profile)
        (cred_ex_record, cred_offer_message) = await cred_manager.prepare_send(
            connection_id,
            verification_method=verification_method,
            cred_proposal=cred_proposal,
            auto_remove=auto_remove,
            replacement_id=replacement_id,
        )
        result = cred_ex_record.serialize()

    except (
        BaseModelError,
        LedgerError,
        StorageError,
        V20CredManagerError,
        V20CredFormatError,
    ) as err:
        # Only log full exception for unexpected errors
        if isinstance(err, (V20CredFormatError, V20CredManagerError)):
            LOGGER.warning(f"Error preparing credential offer: {err.roll_up}")
        else:
            LOGGER.exception("Error preparing credential offer")

        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        await report_problem(
            err,
            ProblemReportReason.ISSUANCE_ABANDONED.value,
            web.HTTPBadRequest,
            cred_ex_record or conn_record,
            outbound_handler,
        )

    await outbound_handler(
        cred_offer_message,
        connection_id=cred_ex_record.connection_id,
    )

    trace_event(
        context.settings,
        cred_offer_message,
        outcome="credential_exchange_send.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary="Send issuer a credential proposal",
)
@request_schema(V20CredExFreeSchema())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_send_proposal(request: web.BaseRequest):
    """Request handler for sending credential proposal.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    body = await request.json()

    connection_id = body.get("connection_id")
    comment = body.get("comment")
    preview_spec = body.get("credential_preview")
    filt_spec = body.get("filter")
    if not filt_spec:
        raise web.HTTPBadRequest(reason="Missing filter")
    auto_remove = body.get(
        "auto_remove", not profile.settings.get("preserve_exchange_records")
    )
    trace_msg = body.get("trace")

    conn_record = None
    cred_ex_record = None
    try:
        cred_preview = V20CredPreview.deserialize(preview_spec) if preview_spec else None
        async with profile.session() as session:
            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
        if not conn_record.is_ready:
            raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

        cred_manager = V20CredManager(profile)
        cred_ex_record = await cred_manager.create_proposal(
            connection_id=connection_id,
            auto_remove=auto_remove,
            comment=comment,
            cred_preview=cred_preview,
            trace=trace_msg,
            fmt2filter={
                V20CredFormat.Format.get(fmt_api): filt_by_fmt
                for (fmt_api, filt_by_fmt) in filt_spec.items()
            },
        )

        cred_proposal_message = cred_ex_record.cred_proposal
        result = cred_ex_record.serialize()

    except (BaseModelError, StorageError) as err:
        LOGGER.exception("Error preparing credential proposal")
        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        # other party cannot yet receive a problem report about our failed protocol start
        raise web.HTTPBadRequest(reason=err.roll_up)

    await outbound_handler(cred_proposal_message, connection_id=connection_id)

    trace_event(
        context.settings,
        cred_proposal_message,
        outcome="credential_exchange_send_proposal.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


async def _create_free_offer(
    profile: Profile,
    filt_spec: Optional[Mapping] = None,
    connection_id: Optional[str] = None,
    auto_issue: bool = False,
    auto_remove: bool = False,
    replacement_id: Optional[str] = None,
    preview_spec: Optional[dict] = None,
    comment: Optional[str] = None,
    trace_msg: Optional[bool] = None,
):
    """Create a credential offer and related exchange record."""

    cred_preview = V20CredPreview.deserialize(preview_spec) if preview_spec else None
    cred_proposal = V20CredProposal(
        comment=comment,
        credential_preview=cred_preview,
        **_formats_filters(filt_spec),
    )
    cred_proposal.assign_trace_decorator(
        profile.settings,
        trace_msg,
    )

    cred_ex_record = V20CredExRecord(
        connection_id=connection_id,
        initiator=V20CredExRecord.INITIATOR_SELF,
        role=V20CredExRecord.ROLE_ISSUER,
        cred_proposal=cred_proposal.serialize(),
        auto_issue=auto_issue,
        auto_remove=auto_remove,
        trace=trace_msg,
    )

    cred_manager = V20CredManager(profile)
    try:
        (cred_ex_record, cred_offer_message) = await cred_manager.create_offer(
            cred_ex_record,
            comment=comment,
            replacement_id=replacement_id,
        )
    except ValueError as err:
        LOGGER.exception(f"Error creating credential offer: {err}")
        async with profile.session() as session:
            await cred_ex_record.save_error_state(session, reason=err)
        raise web.HTTPBadRequest(reason=err)

    return (cred_ex_record, cred_offer_message)


@docs(
    tags=["issue-credential v2.0"],
    summary="Create a credential offer, independent of any proposal or connection",
)
@request_schema(V20CredOfferConnFreeRequestSchema())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_create_free_offer(request: web.BaseRequest):
    """Request handler for creating free credential offer.

    Unlike with `send-offer`, this credential exchange is not tied to a specific
    connection. It must be dispatched out-of-band by the controller.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile

    body = await request.json()

    auto_issue = body.get(
        "auto_issue", context.settings.get("debug.auto_respond_credential_request")
    )
    auto_remove = body.get(
        "auto_remove", not profile.settings.get("preserve_exchange_records")
    )
    replacement_id = body.get("replacement_id")
    comment = body.get("comment")
    preview_spec = body.get("credential_preview")
    filt_spec = body.get("filter")
    if not filt_spec:
        raise web.HTTPBadRequest(reason="Missing filter")
    trace_msg = body.get("trace")
    cred_ex_record = None
    try:
        (cred_ex_record, cred_offer_message) = await _create_free_offer(
            profile=profile,
            filt_spec=filt_spec,
            auto_issue=auto_issue,
            auto_remove=auto_remove,
            replacement_id=replacement_id,
            preview_spec=preview_spec,
            comment=comment,
            trace_msg=trace_msg,
        )
        result = cred_ex_record.serialize()
    except (
        BaseModelError,
        LedgerError,
        V20CredFormatError,
        V20CredManagerError,
    ) as err:
        LOGGER.exception("Error creating free credential offer")
        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        raise web.HTTPBadRequest(reason=err.roll_up)
    trace_event(
        context.settings,
        cred_offer_message,
        outcome="credential_exchange_create_free_offer.END",
        perf_counter=r_time,
    )
    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary="Send holder a credential offer, independent of any proposal",
)
@request_schema(V20CredOfferRequestSchema())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_send_free_offer(request: web.BaseRequest):
    """Request handler for sending free credential offer.

    An issuer initiates a such a credential offer, free from any
    holder-initiated corresponding credential proposal with preview.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    body = await request.json()

    connection_id = body.get("connection_id")
    filt_spec = body.get("filter")
    if not filt_spec:
        raise web.HTTPBadRequest(reason="Missing filter")
    auto_issue = body.get(
        "auto_issue", context.settings.get("debug.auto_respond_credential_request")
    )
    auto_remove = body.get(
        "auto_remove", not profile.settings.get("preserve_exchange_records")
    )
    replacement_id = body.get("replacement_id")
    comment = body.get("comment")
    preview_spec = body.get("credential_preview")
    trace_msg = body.get("trace")

    cred_ex_record = None
    conn_record = None
    try:
        async with profile.session() as session:
            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
        if not conn_record.is_ready:
            raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

        cred_ex_record, cred_offer_message = await _create_free_offer(
            profile=profile,
            filt_spec=filt_spec,
            connection_id=connection_id,
            auto_issue=auto_issue,
            auto_remove=auto_remove,
            preview_spec=preview_spec,
            comment=comment,
            trace_msg=trace_msg,
            replacement_id=replacement_id,
        )
        result = cred_ex_record.serialize()

    except (
        BaseModelError,
        AnonCredsIssuerError,
        IndyIssuerError,
        LedgerError,
        StorageNotFoundError,
        V20CredFormatError,
        V20CredManagerError,
    ) as err:
        LOGGER.exception("Error preparing free credential offer")
        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        # other party cannot yet receive a problem report about our failed protocol start
        raise web.HTTPBadRequest(reason=err.roll_up)

    await outbound_handler(cred_offer_message, connection_id=connection_id)

    trace_event(
        context.settings,
        cred_offer_message,
        outcome="credential_exchange_send_free_offer.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary="Send holder a credential offer in reference to a proposal with preview",
)
@match_info_schema(V20CredExIdMatchInfoSchema())
@request_schema(V20CredBoundOfferRequestSchema())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_send_bound_offer(request: web.BaseRequest):
    """Request handler for sending bound credential offer.

    A holder initiates this sequence with a credential proposal; this message
    responds with an offer bound to the proposal.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    body = await request.json() if request.body_exists else {}
    filt_spec = body.get("filter")
    preview_spec = body.get("counter_preview")

    cred_ex_id = request.match_info["cred_ex_id"]
    cred_ex_record = None
    conn_record = None
    try:
        async with profile.session() as session:
            try:
                cred_ex_record = await V20CredExRecord.retrieve_by_id(
                    session,
                    cred_ex_id,
                )
            except StorageNotFoundError as err:
                raise web.HTTPNotFound(reason=err.roll_up) from err

            connection_id = cred_ex_record.connection_id
            if cred_ex_record.state != (
                V20CredExRecord.STATE_PROPOSAL_RECEIVED
            ):  # check state here: manager call creates free offers too
                raise V20CredManagerError(
                    f"Credential exchange record {cred_ex_record.cred_ex_id} "
                    f"in {cred_ex_record.state} state "
                    f"(must be {V20CredExRecord.STATE_PROPOSAL_RECEIVED})"
                )

            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
            if not conn_record.is_ready:
                raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

        cred_manager = V20CredManager(profile)
        (cred_ex_record, cred_offer_message) = await cred_manager.create_offer(
            cred_ex_record,
            counter_proposal=(
                V20CredProposal(
                    comment=None,
                    credential_preview=V20CredPreview.deserialize(preview_spec),
                    **_formats_filters(filt_spec),
                )
                if preview_spec
                else None
            ),
            comment=None,
        )

        result = cred_ex_record.serialize()

    except (
        BaseModelError,
        AnonCredsIssuerError,
        IndyIssuerError,
        LedgerError,
        StorageError,
        V20CredFormatError,
        V20CredManagerError,
    ) as err:
        LOGGER.exception("Error preparing bound credential offer")
        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        await report_problem(
            err,
            ProblemReportReason.ISSUANCE_ABANDONED.value,
            web.HTTPBadRequest,
            cred_ex_record,
            outbound_handler,
        )
    except LinkedDataProofException as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    await outbound_handler(cred_offer_message, connection_id=connection_id)

    trace_event(
        context.settings,
        cred_offer_message,
        outcome="credential_exchange_send_bound_offer.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary=(
        "Send issuer a credential request not bound to an existing thread."
        " Indy credentials cannot start at a request"
    ),
)
@request_schema(V20CredRequestFreeSchema())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_send_free_request(request: web.BaseRequest):
    """Request handler for sending free credential request.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    body = await request.json()

    connection_id = body.get("connection_id")
    comment = body.get("comment")
    filt_spec = body.get("filter")
    if not filt_spec:
        raise web.HTTPBadRequest(reason="Missing filter")
    auto_remove = body.get(
        "auto_remove", not profile.settings.get("preserve_exchange_records")
    )
    trace_msg = body.get("trace")
    holder_did = body.get("holder_did")

    conn_record = None
    cred_ex_record = None
    try:
        try:
            async with profile.session() as session:
                conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
            if not conn_record.is_ready:
                raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")
        except StorageNotFoundError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

        cred_manager = V20CredManager(profile)

        cred_proposal = V20CredProposal(
            comment=comment,
            **_formats_filters(filt_spec),
        )

        cred_ex_record = V20CredExRecord(
            connection_id=connection_id,
            auto_remove=auto_remove,
            cred_proposal=cred_proposal.serialize(),
            initiator=V20CredExRecord.INITIATOR_SELF,
            role=V20CredExRecord.ROLE_HOLDER,
            trace=trace_msg,
        )

        cred_ex_record, cred_request_message = await cred_manager.create_request(
            cred_ex_record=cred_ex_record,
            holder_did=holder_did,
            comment=comment,
        )

        result = cred_ex_record.serialize()

    except (
        BaseModelError,
        AnonCredsHolderError,
        IndyHolderError,
        LedgerError,
        StorageError,
        V20CredManagerError,
    ) as err:
        LOGGER.exception("Error preparing free credential request")
        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        # other party cannot yet receive a problem report about our failed protocol start
        raise web.HTTPBadRequest(reason=err.roll_up)

    await outbound_handler(cred_request_message, connection_id=connection_id)

    trace_event(
        context.settings,
        cred_request_message,
        outcome="credential_exchange_send_free_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary="Send issuer a credential request",
)
@match_info_schema(V20CredExIdMatchInfoSchema())
@request_schema(V20CredRequestRequestSchema())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_send_bound_request(request: web.BaseRequest):
    """Request handler for sending credential request.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    try:
        body = await request.json() or {}
        holder_did = body.get("holder_did")
        auto_remove = body.get(
            "auto_remove", not profile.settings.get("preserve_exchange_records")
        )
    except JSONDecodeError:
        holder_did = None
        auto_remove = not profile.settings.get("preserve_exchange_records")

    cred_ex_id = request.match_info["cred_ex_id"]

    cred_ex_record = None
    conn_record = None
    try:
        async with profile.session() as session:
            try:
                cred_ex_record = await V20CredExRecord.retrieve_by_id(
                    session,
                    cred_ex_id,
                )
            except StorageNotFoundError as err:
                raise web.HTTPNotFound(reason=err.roll_up) from err

            conn_record = None
            if cred_ex_record.connection_id:
                try:
                    conn_record = await ConnRecord.retrieve_by_id(
                        session, cred_ex_record.connection_id
                    )
                except StorageNotFoundError as err:
                    raise web.HTTPBadRequest(reason=err.roll_up) from err

        if conn_record and not conn_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {cred_ex_record.connection_id} not ready"
            )

        if conn_record or holder_did:
            holder_did = holder_did or conn_record.my_did
        else:
            # Need to get the holder DID from the out of band record
            async with profile.session() as session:
                oob_record = await OobRecord.retrieve_by_tag_filter(
                    session,
                    {"invi_msg_id": cred_ex_record.cred_offer._thread.pthid},
                )
                # Transform recipient key into did
                holder_did = default_did_from_verkey(oob_record.our_recipient_key)

        # assign the auto_remove flag from above...
        cred_ex_record.auto_remove = auto_remove

        cred_manager = V20CredManager(profile)
        cred_ex_record, cred_request_message = await cred_manager.create_request(
            cred_ex_record,
            holder_did,
        )

        result = cred_ex_record.serialize()

    except (
        BaseModelError,
        AnonCredsHolderError,
        IndyHolderError,
        LedgerError,
        StorageError,
        V20CredFormatError,
        V20CredManagerError,
    ) as err:
        LOGGER.exception("Error preparing bound credential request")
        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        await report_problem(
            err,
            ProblemReportReason.ISSUANCE_ABANDONED.value,
            web.HTTPBadRequest,
            cred_ex_record,
            outbound_handler,
        )

    await outbound_handler(
        cred_request_message, connection_id=cred_ex_record.connection_id
    )

    trace_event(
        context.settings,
        cred_request_message,
        outcome="credential_exchange_send_bound_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary="Send holder a credential",
)
@match_info_schema(V20CredExIdMatchInfoSchema())
@request_schema(V20CredIssueRequestSchema())
@response_schema(V20CredExRecordDetailSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_issue(request: web.BaseRequest):
    """Request handler for sending credential.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    body = await request.json()
    comment = body.get("comment")

    cred_ex_id = request.match_info["cred_ex_id"]

    cred_ex_record = None
    conn_record = None
    try:
        async with profile.session() as session:
            try:
                cred_ex_record = await V20CredExRecord.retrieve_by_id(
                    session,
                    cred_ex_id,
                )
            except StorageNotFoundError as err:
                raise web.HTTPNotFound(reason=err.roll_up) from err

            conn_record = None
            if cred_ex_record.connection_id:
                conn_record = await ConnRecord.retrieve_by_id(
                    session, cred_ex_record.connection_id
                )
        if conn_record and not conn_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {cred_ex_record.connection_id} not ready"
            )

        cred_manager = V20CredManager(profile)
        (cred_ex_record, cred_issue_message) = await cred_manager.issue_credential(
            cred_ex_record,
            comment=comment,
        )

        details = await _get_attached_credentials(profile, cred_ex_record)
        result = _format_result_with_details(cred_ex_record, details)

    except (
        BaseModelError,
        AnonCredsIssuerError,
        IndyIssuerError,
        LedgerError,
        StorageError,
        V20CredFormatError,
        V20CredManagerError,
    ) as err:
        LOGGER.exception("Error preparing issued credential")
        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        await report_problem(
            err,
            ProblemReportReason.ISSUANCE_ABANDONED.value,
            web.HTTPBadRequest,
            cred_ex_record,
            outbound_handler,
        )

    await outbound_handler(cred_issue_message, connection_id=cred_ex_record.connection_id)

    trace_event(
        context.settings,
        cred_issue_message,
        outcome="credential_exchange_issue.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary="Store a received credential",
)
@match_info_schema(V20CredExIdMatchInfoSchema())
@request_schema(V20CredStoreRequestSchema())
@response_schema(V20CredExRecordDetailSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_store(request: web.BaseRequest):
    """Request handler for storing credential.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    try:
        body = await request.json() or {}
        cred_id = body.get("credential_id")
    except JSONDecodeError:
        cred_id = None

    cred_ex_id = request.match_info["cred_ex_id"]
    cred_ex_record = None
    conn_record = None
    try:
        async with profile.session() as session:
            try:
                cred_ex_record = await V20CredExRecord.retrieve_by_id(
                    session,
                    cred_ex_id,
                )
            except StorageNotFoundError as err:
                raise web.HTTPNotFound(reason=err.roll_up) from err

            conn_record = None
            if cred_ex_record.connection_id:
                conn_record = await ConnRecord.retrieve_by_id(
                    session, cred_ex_record.connection_id
                )
            if conn_record and not conn_record.is_ready:
                raise web.HTTPForbidden(
                    reason=f"Connection {cred_ex_record.connection_id} not ready"
                )

        cred_manager = V20CredManager(profile)
        cred_ex_record = await cred_manager.store_credential(cred_ex_record, cred_id)

    except (
        AnonCredsHolderError,
        IndyHolderError,
        StorageError,
        V20CredManagerError,
    ) as err:  # treat failure to store as mangled on receipt hence protocol error
        LOGGER.exception("Error storing issued credential")
        if cred_ex_record:
            async with profile.session() as session:
                await cred_ex_record.save_error_state(session, reason=err.roll_up)
        await report_problem(
            err,
            ProblemReportReason.ISSUANCE_ABANDONED.value,
            web.HTTPBadRequest,
            cred_ex_record,
            outbound_handler,
        )

    try:
        # fetch these early, before potential removal
        details = await _get_attached_credentials(profile, cred_ex_record)

        # the record may be auto-removed here
        (
            cred_ex_record,
            cred_ack_message,
        ) = await cred_manager.send_cred_ack(cred_ex_record)

        result = _format_result_with_details(cred_ex_record, details)

    except (
        BaseModelError,
        StorageError,
        V20CredFormatError,
        V20CredManagerError,
    ) as err:
        # protocol finished OK: do not send problem report nor set record state error
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    trace_event(
        context.settings,
        cred_ack_message,
        outcome="credential_exchange_store.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential v2.0"],
    summary="Remove an existing credential exchange record",
)
@match_info_schema(V20CredExIdMatchInfoSchema())
@response_schema(V20IssueCredentialModuleResponseSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_remove(request: web.BaseRequest):
    """Request handler for removing a credential exchange record.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]

    cred_ex_id = request.match_info["cred_ex_id"]
    try:
        cred_manager = V20CredManager(context.profile)
        await cred_manager.delete_cred_ex_record(cred_ex_id)
    except StorageNotFoundError as err:  # not a protocol error
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:  # not a protocol error
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({})


@docs(
    tags=["issue-credential v2.0"],
    summary="Send a problem report for credential exchange",
)
@match_info_schema(V20CredExIdMatchInfoSchema())
@request_schema(V20CredIssueProblemReportRequestSchema())
@response_schema(V20IssueCredentialModuleResponseSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_problem_report(request: web.BaseRequest):
    """Request handler for sending problem report.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    profile = context.profile
    outbound_handler = request["outbound_message_router"]

    cred_ex_id = request.match_info["cred_ex_id"]
    body = await request.json()
    description = body["description"]

    try:
        async with profile.session() as session:
            cred_ex_record = await V20CredExRecord.retrieve_by_id(session, cred_ex_id)
            report = problem_report_for_record(cred_ex_record, description)
            await cred_ex_record.save_error_state(
                session,
                reason=f"created problem report: {description}",
            )
    except StorageNotFoundError as err:  # other party does not care about meta-problems
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    await outbound_handler(report, connection_id=cred_ex_record.connection_id)

    return web.json_response({})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get(
                "/issue-credential-2.0/records",
                credential_exchange_list,
                allow_head=False,
            ),
            web.post(
                "/issue-credential-2.0/create-offer",
                credential_exchange_create_free_offer,
            ),
            web.get(
                "/issue-credential-2.0/records/{cred_ex_id}",
                credential_exchange_retrieve,
                allow_head=False,
            ),
            web.post("/issue-credential-2.0/create", credential_exchange_create),
            web.post("/issue-credential-2.0/send", credential_exchange_send),
            web.post(
                "/issue-credential-2.0/send-proposal", credential_exchange_send_proposal
            ),
            web.post(
                "/issue-credential-2.0/send-offer", credential_exchange_send_free_offer
            ),
            web.post(
                "/issue-credential-2.0/send-request",
                credential_exchange_send_free_request,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/send-offer",
                credential_exchange_send_bound_offer,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/send-request",
                credential_exchange_send_bound_request,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/issue",
                credential_exchange_issue,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/store",
                credential_exchange_store,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/problem-report",
                credential_exchange_problem_report,
            ),
            web.delete(
                "/issue-credential-2.0/records/{cred_ex_id}",
                credential_exchange_remove,
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
            "name": "issue-credential v2.0",
            "description": "Credential issue v2.0",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
