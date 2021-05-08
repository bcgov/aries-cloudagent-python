"""Admin routes for presentations."""

import json

from typing import Mapping

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields, validate, validates_schema, ValidationError

from ....admin.request_context import AdminRequestContext
from ....connections.models.conn_record import ConnRecord
from ....indy.holder import IndyHolder, IndyHolderError
from ....indy.sdk.models.cred_precis import IndyCredPrecisSchema
from ....indy.sdk.models.proof import IndyPresSpecSchema
from ....indy.sdk.models.proof_request import IndyProofRequestSchema
from ....indy.util import generate_pr_nonce
from ....ledger.error import LedgerError
from ....messaging.decorators.attach_decorator import AttachDecorator
from ....messaging.models.base import BaseModelError
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import (
    INDY_EXTRA_WQL,
    NUM_STR_NATURAL,
    NUM_STR_WHOLE,
    UUIDFour,
    UUID4,
)
from ....storage.error import StorageError, StorageNotFoundError
from ....utils.tracing import trace_event, get_timer, AdminAPIMessageTracingSchema
from ....wallet.error import WalletNotFoundError

from ...problem_report.v1_0 import internal_error

from .manager import V20PresManager
from .message_types import (
    ATTACHMENT_FORMAT,
    PRES_20_PROPOSAL,
    PRES_20_REQUEST,
    SPEC_URI,
)
from .messages.pres_format import V20PresFormat
from .messages.pres_proposal import V20PresProposal
from .messages.pres_request import V20PresRequest
from .models.pres_exchange import V20PresExRecord, V20PresExRecordSchema


class V20PresentProofModuleResponseSchema(OpenAPISchema):
    """Response schema for Present Proof Module."""


class V20PresExRecordListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for presentation exchange list query."""

    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    thread_id = fields.UUID(
        description="Thread identifier",
        required=False,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    role = fields.Str(
        description="Role assigned in presentation exchange",
        required=False,
        validate=validate.OneOf(
            [
                getattr(V20PresExRecord, m)
                for m in vars(V20PresExRecord)
                if m.startswith("ROLE_")
            ]
        ),
    )
    state = fields.Str(
        description="Presentation exchange state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(V20PresExRecord, m)
                for m in vars(V20PresExRecord)
                if m.startswith("STATE_")
            ]
        ),
    )


class V20PresExRecordListSchema(OpenAPISchema):
    """Result schema for a presentation exchange query."""

    results = fields.List(
        fields.Nested(V20PresExRecordSchema()),
        description="Presentation exchange records",
    )


class DIFPresProposalSchema(OpenAPISchema):
    """DIF presentation proposal schema placeholder."""

    some_dif = fields.Str(
        description="Placeholder for W3C/DIF/JSON-LD presentation proposal format",
        required=False,
    )


class DIFPresRequestSchema(OpenAPISchema):
    """DIF presentation request schema placeholder."""

    some_dif = fields.Str(
        description="Placeholder for W3C/DIF/JSON-LD presentation request format",
        required=False,
    )


class DIFPresSpecSchema(OpenAPISchema):
    """DIF presentation schema specification placeholder."""

    some_dif = fields.Str(
        description="Placeholder for W3C/DIF/JSON-LD presentation format",
        required=False,
    )


class V20PresProposalByFormatSchema(OpenAPISchema):
    """Schema for presentation proposal per format."""

    indy = fields.Nested(
        IndyProofRequestSchema,
        required=False,
        description="Presentation proposal for indy",
    )
    dif = fields.Nested(
        DIFPresProposalSchema,
        required=False,
        description="Presentation proposal for DIF",
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """
        Validate schema fields: data must have at least one format.

        Args:
            data: The data to validate

        Raises:
            ValidationError: if data has no formats

        """
        if not any(f.api in data for f in V20PresFormat.Format):
            raise ValidationError(
                "V20PresProposalByFormatSchema requires indy, dif, or both"
            )


class V20PresProposalRequestSchema(AdminAPIMessageTracingSchema):
    """Request schema for sending a presentation proposal admin message."""

    connection_id = fields.UUID(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )
    comment = fields.Str(
        description="Human-readable comment", required=False, allow_none=True
    )
    presentation_proposal = fields.Nested(
        V20PresProposalByFormatSchema(),
        required=True,
    )
    auto_present = fields.Boolean(
        description=(
            "Whether to respond automatically to presentation requests, building "
            "and presenting requested proof"
        ),
        required=False,
        default=False,
    )
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )


class V20PresRequestByFormatSchema(OpenAPISchema):
    """Presentation request per format."""

    indy = fields.Nested(
        IndyProofRequestSchema,
        required=False,
        description="Presentation request for indy",
    )
    dif = fields.Nested(
        DIFPresRequestSchema,
        required=False,
        description="Presentation request for DIF",
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """
        Validate schema fields: data must have at least one format.

        Args:
            data: The data to validate

        Raises:
            ValidationError: if data has no formats

        """
        if not any(f.api in data for f in V20PresFormat.Format):
            raise ValidationError(
                "V20PresRequestByFormatSchema requires indy, dif, or both"
            )


class V20PresCreateRequestRequestSchema(AdminAPIMessageTracingSchema):
    """Request schema for creating a proof request free of any connection."""

    presentation_request = fields.Nested(V20PresRequestByFormatSchema(), required=True)
    comment = fields.Str(required=False, allow_none=True)
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )


class V20PresSendRequestRequestSchema(V20PresCreateRequestRequestSchema):
    """Request schema for sending a proof request on a connection."""

    connection_id = fields.UUID(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )


class V20PresSpecByFormatRequestSchema(AdminAPIMessageTracingSchema):
    """Presentation specification schema by format, for send-presentation request."""

    indy = fields.Nested(
        IndyPresSpecSchema,
        required=False,
        description="Presentation specification for indy",
    )
    dif = fields.Nested(
        DIFPresSpecSchema,
        required=False,
        description="Presentation specification for DIF",
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """
        Validate schema fields: specify exactly one format.

        Args:
            data: The data to validate

        Raises:
            ValidationError: if data does not have exactly one format.

        """
        if len(data.keys() & {f.api for f in V20PresFormat.Format}) != 1:
            raise ValidationError(
                "V20PresSpecByFormatRequestSchema must specify one presentation format"
            )


class V20CredentialsFetchQueryStringSchema(OpenAPISchema):
    """Parameters and validators for credentials fetch request query string."""

    referent = fields.Str(
        description="Proof request referents of interest, comma-separated",
        required=False,
        example="1_name_uuid,2_score_uuid",
    )
    start = fields.Str(
        description="Start index",
        required=False,
        strict=True,
        **NUM_STR_WHOLE,
    )
    count = fields.Str(
        description="Maximum number to retrieve",
        required=False,
        **NUM_STR_NATURAL,
    )
    extra_query = fields.Str(
        description="(JSON) object mapping referents to extra WQL queries",
        required=False,
        **INDY_EXTRA_WQL,
    )


class V20PresProblemReportRequestSchema(OpenAPISchema):
    """Request schema for sending problem report."""

    description = fields.Str(required=True)


class V20PresExIdMatchInfoSchema(OpenAPISchema):
    """Path parameters for request taking presentation exchange id."""

    pres_ex_id = fields.Str(
        description="Presentation exchange identifier", required=True, **UUID4
    )


async def _add_nonce(indy_proof_request: Mapping) -> Mapping:
    """Add nonce to indy proof request if need be."""

    if not indy_proof_request.get("nonce"):
        indy_proof_request["nonce"] = await generate_pr_nonce()
    return indy_proof_request


def _formats_attach(by_format: Mapping, msg_type: str, spec: str) -> Mapping:
    """Break out formats and proposals/requests/presentations for v2.0 messages."""

    return {
        "formats": [
            V20PresFormat(
                attach_id=fmt_api,
                format_=ATTACHMENT_FORMAT[msg_type][fmt_api],
            )
            for fmt_api in by_format
        ],
        f"{spec}_attach": [
            AttachDecorator.data_base64(mapping=item_by_fmt, ident=fmt_api)
            for (fmt_api, item_by_fmt) in by_format.items()
        ],
    }


@docs(tags=["present-proof v2.0"], summary="Fetch all present-proof exchange records")
@querystring_schema(V20PresExRecordListQueryStringSchema)
@response_schema(V20PresExRecordListSchema(), 200, description="")
async def present_proof_list(request: web.BaseRequest):
    """
    Request handler for searching presentation exchange records.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange list response

    """
    context: AdminRequestContext = request["context"]

    tag_filter = {}
    if "thread_id" in request.query and request.query["thread_id"] != "":
        tag_filter["thread_id"] = request.query["thread_id"]
    post_filter = {
        k: request.query[k]
        for k in ("connection_id", "role", "state")
        if request.query.get(k, "") != ""
    }

    try:
        async with context.session() as session:
            records = await V20PresExRecord.query(
                session=session,
                tag_filter=tag_filter,
                post_filter_positive=post_filter,
            )
        results = [record.serialize() for record in records]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(
    tags=["present-proof v2.0"],
    summary="Fetch a single presentation exchange record",
)
@match_info_schema(V20PresExIdMatchInfoSchema())
@response_schema(V20PresExRecordSchema(), 200, description="")
async def present_proof_retrieve(request: web.BaseRequest):
    """
    Request handler for fetching a single presentation exchange record.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange record response

    """
    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    pres_ex_id = request.match_info["pres_ex_id"]
    pres_ex_record = None
    try:
        async with context.session() as session:
            pres_ex_record = await V20PresExRecord.retrieve_by_id(session, pres_ex_id)
        result = pres_ex_record.serialize()
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, StorageError) as err:
        return await internal_error(
            err, web.HTTPBadRequest, pres_ex_record, outbound_handler
        )

    return web.json_response(result)


@docs(
    tags=["present-proof v2.0"],
    summary="Fetch credentials from wallet for presentation request",
)
@match_info_schema(V20PresExIdMatchInfoSchema())
@querystring_schema(V20CredentialsFetchQueryStringSchema())
@response_schema(IndyCredPrecisSchema(many=True), 200, description="")
async def present_proof_credentials_list(request: web.BaseRequest):
    """
    Request handler for searching applicable credential records.

    Args:
        request: aiohttp request object

    Returns:
        The credential list response

    """
    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    pres_ex_id = request.match_info["pres_ex_id"]
    referents = request.query.get("referent")
    pres_referents = (r.strip() for r in referents.split(",")) if referents else ()

    try:
        async with context.session() as session:
            pres_ex_record = await V20PresExRecord.retrieve_by_id(session, pres_ex_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    start = request.query.get("start")
    count = request.query.get("count")

    # url encoded json extra_query
    encoded_extra_query = request.query.get("extra_query") or "{}"
    extra_query = json.loads(encoded_extra_query)

    # defaults
    start = int(start) if isinstance(start, str) else 0
    count = int(count) if isinstance(count, str) else 10

    holder = context.profile.inject(IndyHolder)
    try:
        # TODO: allow for choice of format from those specified in pres req
        pres_request = pres_ex_record.by_format["pres_request"].get(
            V20PresFormat.Format.INDY.api
        )
        credentials = await holder.get_credentials_for_presentation_request_by_referent(
            pres_request,
            pres_referents,
            start,
            count,
            extra_query,
        )
    except IndyHolderError as err:
        return await internal_error(
            err, web.HTTPBadRequest, pres_ex_record, outbound_handler
        )

    pres_ex_record.log_state(
        "Retrieved presentation credentials",
        {
            "presentation_exchange_id": pres_ex_id,
            "referents": pres_referents,
            "extra_query": extra_query,
            "credentials": credentials,
        },
        settings=context.settings,
    )
    return web.json_response(credentials)


@docs(tags=["present-proof v2.0"], summary="Sends a presentation proposal")
@request_schema(V20PresProposalRequestSchema())
@response_schema(V20PresExRecordSchema(), 200, description="")
async def present_proof_send_proposal(request: web.BaseRequest):
    """
    Request handler for sending a presentation proposal.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    body = await request.json()

    comment = body.get("comment")
    connection_id = body.get("connection_id")

    pres_proposal = body.get("presentation_proposal")
    conn_record = None
    async with context.session() as session:
        try:
            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
            pres_proposal_message = V20PresProposal(
                comment=comment,
                **_formats_attach(pres_proposal, PRES_20_PROPOSAL, "proposals"),
            )
        except (BaseModelError, StorageError) as err:
            return await internal_error(
                err, web.HTTPBadRequest, conn_record, outbound_handler
            )

    if not conn_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    trace_msg = body.get("trace")
    pres_proposal_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )
    auto_present = body.get(
        "auto_present", context.settings.get("debug.auto_respond_presentation_request")
    )

    pres_manager = V20PresManager(context.profile)
    pres_ex_record = None
    try:
        pres_ex_record = await pres_manager.create_exchange_for_proposal(
            connection_id=connection_id,
            pres_proposal_message=pres_proposal_message,
            auto_present=auto_present,
        )
        result = pres_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        return await internal_error(
            err,
            web.HTTPBadRequest,
            pres_ex_record or conn_record,
            outbound_handler,
        )

    await outbound_handler(pres_proposal_message, connection_id=connection_id)

    trace_event(
        context.settings,
        pres_proposal_message,
        outcome="presentation_exchange_propose.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["present-proof v2.0"],
    summary="Creates a presentation request not bound to any proposal or connection",
)
@request_schema(V20PresCreateRequestRequestSchema())
@response_schema(V20PresExRecordSchema(), 200, description="")
async def present_proof_create_request(request: web.BaseRequest):
    """
    Request handler for creating a free presentation request.

    The presentation request will not be bound to any proposal
    or existing connection.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    body = await request.json()

    comment = body.get("comment")
    pres_request_spec = body.get("presentation_request")
    if pres_request_spec and V20PresFormat.Format.INDY.api in pres_request_spec:
        await _add_nonce(pres_request_spec[V20PresFormat.Format.INDY.api])

    pres_request_message = V20PresRequest(
        comment=comment,
        will_confirm=True,
        **_formats_attach(pres_request_spec, PRES_20_REQUEST, "request_presentations"),
    )
    trace_msg = body.get("trace")
    pres_request_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )

    pres_manager = V20PresManager(context.profile)
    pres_ex_record = None
    try:
        pres_ex_record = await pres_manager.create_exchange_for_request(
            connection_id=None,
            pres_request_message=pres_request_message,
        )
        result = pres_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        return await internal_error(
            err, web.HTTPBadRequest, pres_ex_record, outbound_handler
        )

    await outbound_handler(pres_request_message, connection_id=None)

    trace_event(
        context.settings,
        pres_request_message,
        outcome="presentation_exchange_create_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["present-proof v2.0"],
    summary="Sends a free presentation request not bound to any proposal",
)
@request_schema(V20PresSendRequestRequestSchema())
@response_schema(V20PresExRecordSchema(), 200, description="")
async def present_proof_send_free_request(request: web.BaseRequest):
    """
    Request handler for sending a presentation request free from any proposal.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    body = await request.json()

    connection_id = body.get("connection_id")
    async with context.session() as session:
        try:
            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
        except StorageNotFoundError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not conn_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    comment = body.get("comment")
    pres_request_spec = body.get("presentation_request")
    if pres_request_spec and V20PresFormat.Format.INDY.api in pres_request_spec:
        await _add_nonce(pres_request_spec[V20PresFormat.Format.INDY.api])
    pres_request_message = V20PresRequest(
        comment=comment,
        will_confirm=True,
        **_formats_attach(pres_request_spec, PRES_20_REQUEST, "request_presentations"),
    )
    trace_msg = body.get("trace")
    pres_request_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )

    pres_manager = V20PresManager(context.profile)
    pres_ex_record = None
    try:
        (pres_ex_record) = await pres_manager.create_exchange_for_request(
            connection_id=connection_id,
            pres_request_message=pres_request_message,
        )
        result = pres_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        return await internal_error(
            err,
            web.HTTPBadRequest,
            pres_ex_record or conn_record,
            outbound_handler,
        )

    await outbound_handler(pres_request_message, connection_id=connection_id)

    trace_event(
        context.settings,
        pres_request_message,
        outcome="presentation_exchange_send_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["present-proof v2.0"],
    summary="Sends a presentation request in reference to a proposal",
)
@match_info_schema(V20PresExIdMatchInfoSchema())
@request_schema(AdminAPIMessageTracingSchema())
@response_schema(V20PresExRecordSchema(), 200, description="")
async def present_proof_send_bound_request(request: web.BaseRequest):
    """
    Request handler for sending a presentation request bound to a proposal.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    body = await request.json()

    pres_ex_id = request.match_info["pres_ex_id"]
    pres_ex_record = None
    async with context.session() as session:
        try:
            pres_ex_record = await V20PresExRecord.retrieve_by_id(session, pres_ex_id)
        except StorageNotFoundError as err:
            return await internal_error(
                err, web.HTTPNotFound, pres_ex_record, outbound_handler
            )

        if pres_ex_record.state != (V20PresExRecord.STATE_PROPOSAL_RECEIVED):
            raise web.HTTPBadRequest(
                reason=(
                    f"Presentation exchange {pres_ex_id} "
                    f"in {pres_ex_record.state} state "
                    f"(must be {V20PresExRecord.STATE_PROPOSAL_RECEIVED})"
                )
            )
        connection_id = pres_ex_record.connection_id

        try:
            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
        except StorageError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not conn_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    pres_manager = V20PresManager(context.profile)
    try:
        (
            pres_ex_record,
            pres_request_message,
        ) = await pres_manager.create_bound_request(pres_ex_record)
        result = pres_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        return await internal_error(
            err,
            web.HTTPBadRequest,
            pres_ex_record or conn_record,
            outbound_handler,
        )

    trace_msg = body.get("trace")
    pres_request_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )
    await outbound_handler(pres_request_message, connection_id=connection_id)

    trace_event(
        context.settings,
        pres_request_message,
        outcome="presentation_exchange_send_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["present-proof v2.0"], summary="Sends a proof presentation")
@match_info_schema(V20PresExIdMatchInfoSchema())
@request_schema(V20PresSpecByFormatRequestSchema())
@response_schema(V20PresExRecordSchema(), description="")
async def present_proof_send_presentation(request: web.BaseRequest):
    """
    Request handler for sending a presentation.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]
    pres_ex_id = request.match_info["pres_ex_id"]
    body = await request.json()
    fmt = V20PresFormat.Format.get([f for f in body][0])  # "indy" xor "dif"

    pres_ex_record = None
    async with context.session() as session:
        try:
            pres_ex_record = await V20PresExRecord.retrieve_by_id(session, pres_ex_id)
        except StorageNotFoundError as err:
            return await internal_error(
                err, web.HTTPNotFound, pres_ex_record, outbound_handler
            )

        if pres_ex_record.state != (V20PresExRecord.STATE_REQUEST_RECEIVED):
            raise web.HTTPBadRequest(
                reason=(
                    f"Presentation exchange {pres_ex_id} "
                    f"in {pres_ex_record.state} state "
                    f"(must be {V20PresExRecord.STATE_REQUEST_RECEIVED})"
                )
            )

        connection_id = pres_ex_record.connection_id
        try:
            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
        except StorageNotFoundError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not conn_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    pres_manager = V20PresManager(context.profile)
    try:
        indy_spec = body.get(V20PresFormat.Format.INDY.api)  # TODO: accommodate DIF
        pres_ex_record, pres_message = await pres_manager.create_pres(
            pres_ex_record,
            {
                "self_attested_attributes": indy_spec["self_attested_attributes"],
                "requested_attributes": indy_spec["requested_attributes"],
                "requested_predicates": indy_spec["requested_predicates"],
            },
            comment=body.get("comment"),
            format_=fmt,
        )
        result = pres_ex_record.serialize()
    except (
        BaseModelError,
        IndyHolderError,
        LedgerError,
        StorageError,
        WalletNotFoundError,
    ) as err:
        return await internal_error(
            err,
            web.HTTPBadRequest,
            pres_ex_record or conn_record,
            outbound_handler,
        )

    trace_msg = body.get("trace")
    pres_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )
    await outbound_handler(pres_message, connection_id=connection_id)

    trace_event(
        context.settings,
        pres_message,
        outcome="presentation_exchange_send_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["present-proof v2.0"], summary="Verify a received presentation")
@match_info_schema(V20PresExIdMatchInfoSchema())
@response_schema(V20PresExRecordSchema(), description="")
async def present_proof_verify_presentation(request: web.BaseRequest):
    """
    Request handler for verifying a presentation request.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    pres_ex_id = request.match_info["pres_ex_id"]

    pres_ex_record = None
    async with context.session() as session:
        try:
            pres_ex_record = await V20PresExRecord.retrieve_by_id(session, pres_ex_id)
        except StorageNotFoundError as err:
            return await internal_error(
                err, web.HTTPNotFound, pres_ex_record, outbound_handler
            )

        if pres_ex_record.state != (V20PresExRecord.STATE_PRESENTATION_RECEIVED):
            raise web.HTTPBadRequest(
                reason=(
                    f"Presentation exchange {pres_ex_id} "
                    f"in {pres_ex_record.state} state "
                    f"(must be {V20PresExRecord.STATE_PRESENTATION_RECEIVED})"
                )
            )

        connection_id = pres_ex_record.connection_id

        try:
            conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
        except StorageError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not conn_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    pres_manager = V20PresManager(context.profile)
    try:
        pres_ex_record = await pres_manager.verify_pres(pres_ex_record)
        result = pres_ex_record.serialize()
    except (LedgerError, BaseModelError) as err:
        return await internal_error(
            err, web.HTTPBadRequest, pres_ex_record, outbound_handler
        )

    trace_event(
        context.settings,
        pres_ex_record,
        outcome="presentation_exchange_verify.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["present-proof v2.0"],
    summary="Send a problem report for presentation exchange",
)
@match_info_schema(V20PresExIdMatchInfoSchema())
@request_schema(V20PresProblemReportRequestSchema())
@response_schema(V20PresentProofModuleResponseSchema(), 200, description="")
async def present_proof_problem_report(request: web.BaseRequest):
    """
    Request handler for sending problem report.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    pres_ex_id = request.match_info["pres_ex_id"]
    body = await request.json()

    pres_manager = V20PresManager(context.profile)

    try:
        async with await context.session() as session:
            pres_ex_record = await V20PresExRecord.retrieve_by_id(session, pres_ex_id)
        report = await pres_manager.create_problem_report(
            pres_ex_record,
            body["description"],
        )
    except StorageNotFoundError as err:
        await internal_error(err, web.HTTPNotFound, None, outbound_handler)
    except StorageError as err:
        await internal_error(err, web.HTTPBadRequest, pres_ex_record, outbound_handler)

    await outbound_handler(report, connection_id=pres_ex_record.connection_id)

    return web.json_response({})


@docs(
    tags=["present-proof v2.0"],
    summary="Remove an existing presentation exchange record",
)
@match_info_schema(V20PresExIdMatchInfoSchema())
@response_schema(V20PresentProofModuleResponseSchema(), description="")
async def present_proof_remove(request: web.BaseRequest):
    """
    Request handler for removing a presentation exchange record.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    pres_ex_id = request.match_info["pres_ex_id"]
    pres_ex_record = None
    try:
        async with context.session() as session:
            pres_ex_record = await V20PresExRecord.retrieve_by_id(session, pres_ex_id)
            await pres_ex_record.delete_record(session)
    except StorageNotFoundError as err:
        return await internal_error(
            err, web.HTTPNotFound, pres_ex_record, outbound_handler
        )
    except StorageError as err:
        return await internal_error(
            err, web.HTTPBadRequest, pres_ex_record, outbound_handler
        )

    return web.json_response({})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get(
                "/present-proof-2.0/records",
                present_proof_list,
                allow_head=False,
            ),
            web.get(
                "/present-proof-2.0/records/{pres_ex_id}",
                present_proof_retrieve,
                allow_head=False,
            ),
            web.get(
                "/present-proof-2.0/records/{pres_ex_id}/credentials",
                present_proof_credentials_list,
                allow_head=False,
            ),
            web.post(
                "/present-proof-2.0/send-proposal",
                present_proof_send_proposal,
            ),
            web.post(
                "/present-proof-2.0/create-request",
                present_proof_create_request,
            ),
            web.post(
                "/present-proof-2.0/send-request",
                present_proof_send_free_request,
            ),
            web.post(
                "/present-proof-2.0/records/{pres_ex_id}/send-request",
                present_proof_send_bound_request,
            ),
            web.post(
                "/present-proof-2.0/records/{pres_ex_id}/send-presentation",
                present_proof_send_presentation,
            ),
            web.post(
                "/present-proof-2.0/records/{pres_ex_id}/verify-presentation",
                present_proof_verify_presentation,
            ),
            web.post(
                "/present-proof-2.0/records/{pres_ex_id}/problem-report",
                present_proof_problem_report,
            ),
            web.delete(
                "/present-proof-2.0/records/{pres_ex_id}",
                present_proof_remove,
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
            "name": "present-proof v2.0",
            "description": "Proof presentation v2.0",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
