"""Presentation exchange record."""

import logging
from typing import Any, Mapping, Optional, Union

from marshmallow import Schema, fields, validate

from .....core.profile import ProfileSession
from .....messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from .....messaging.valid import UUID4_EXAMPLE
from .....storage.base import StorageError
from ..messages.pres import V20Pres, V20PresSchema
from ..messages.pres_format import V20PresFormat
from ..messages.pres_proposal import V20PresProposal, V20PresProposalSchema
from ..messages.pres_request import V20PresRequest, V20PresRequestSchema
from ..messages.pres_webhook import V20PresExRecordWebhook
from . import UNENCRYPTED_TAGS

LOGGER = logging.getLogger(__name__)


class V20PresExRecord(BaseExchangeRecord):
    """Represents a v2.0 presentation exchange."""

    class Meta:
        """V20PresExRecord metadata."""

        schema_class = "V20PresExRecordSchema"

    RECORD_TYPE = "pres_ex_v20"
    RECORD_ID_NAME = "pres_ex_id"
    RECORD_TOPIC = "present_proof_v2_0"
    TAG_NAMES = {"~thread_id"} if UNENCRYPTED_TAGS else {"thread_id"}

    INITIATOR_SELF = "self"
    INITIATOR_EXTERNAL = "external"

    ROLE_PROVER = "prover"
    ROLE_VERIFIER = "verifier"

    STATE_PROPOSAL_SENT = "proposal-sent"
    STATE_PROPOSAL_RECEIVED = "proposal-received"
    STATE_REQUEST_SENT = "request-sent"
    STATE_REQUEST_RECEIVED = "request-received"
    STATE_PRESENTATION_SENT = "presentation-sent"
    STATE_PRESENTATION_RECEIVED = "presentation-received"
    STATE_DONE = "done"
    STATE_ABANDONED = "abandoned"

    def __init__(
        self,
        *,
        pres_ex_id: Optional[str] = None,
        connection_id: Optional[str] = None,
        thread_id: Optional[str] = None,
        initiator: Optional[str] = None,
        role: Optional[str] = None,
        state: Optional[str] = None,
        pres_proposal: Union[V20PresProposal, Mapping] = None,  # aries message
        pres_request: Union[V20PresRequest, Mapping] = None,  # aries message
        pres: Union[V20Pres, Mapping] = None,  # aries message
        verified: Optional[str] = None,
        verified_msgs: Optional[list] = None,
        auto_present: bool = False,
        auto_verify: bool = False,
        error_msg: Optional[str] = None,
        trace: bool = False,  # backward compat: BaseRecord.FromStorage()
        by_format: Optional[Mapping] = None,  # backward compat: BaseRecord.FromStorage()
        auto_remove: bool = False,
        **kwargs,
    ):
        """Initialize a new PresExRecord."""
        super().__init__(pres_ex_id, state, trace=trace, **kwargs)
        self.connection_id = connection_id
        self.thread_id = thread_id
        self.initiator = initiator
        self.role = role
        self.state = state
        self._pres_proposal = V20PresProposal.serde(pres_proposal)
        self._pres_request = V20PresRequest.serde(pres_request)
        self._pres = V20Pres.serde(pres)
        self.verified = verified
        self.verified_msgs = verified_msgs
        self.auto_present = auto_present
        self.auto_verify = auto_verify
        self.error_msg = error_msg
        self.auto_remove = auto_remove

    @property
    def pres_ex_id(self) -> str:
        """Accessor for the ID associated with this exchange record."""
        return self._id

    @property
    def by_format(self) -> Mapping:
        """Record proposal, request, and presentation attachments by format."""
        result = {}
        for item, cls in {
            "pres_proposal": V20PresProposal,  # note: proof request attached for indy
            "pres_request": V20PresRequest,
            "pres": V20Pres,
        }.items():
            msg = getattr(self, item)
            if msg:
                result.update(
                    {
                        item: {
                            V20PresFormat.Format.get(f.format).api: msg.attachment(
                                V20PresFormat.Format.get(f.format)
                            )
                            for f in msg.formats
                        }
                    }
                )

        return result

    @property
    def pres_proposal(self) -> V20PresProposal:
        """Accessor; get deserialized view."""
        return None if self._pres_proposal is None else self._pres_proposal.de

    @pres_proposal.setter
    def pres_proposal(self, value):
        """Setter; store de/serialized views."""
        self._pres_proposal = V20PresProposal.serde(value)

    @property
    def pres_request(self) -> V20PresRequest:
        """Accessor; get deserialized view."""
        return None if self._pres_request is None else self._pres_request.de

    @pres_request.setter
    def pres_request(self, value):
        """Setter; store de/serialized views."""
        self._pres_request = V20PresRequest.serde(value)

    @property
    def pres(self) -> V20Pres:
        """Accessor; get deserialized view."""
        return None if self._pres is None else self._pres.de

    @pres.setter
    def pres(self, value):
        """Setter; store de/serialized views."""
        self._pres = V20Pres.serde(value)

    async def save_error_state(
        self,
        session: ProfileSession,
        *,
        state: Optional[str] = None,
        reason: Optional[str] = None,
        log_params: Mapping[str, Any] = None,
        log_override: bool = False,
    ):
        """Save record error state if need be; log and swallow any storage error.

        Args:
            session: The profile session to use
            state: The state to set
            reason: A reason to add to the log
            log_params: Additional parameters to log
            log_override: Override configured logging regimen, print to stderr instead
        """

        if self._last_state == state:  # already done
            return

        self.state = state or V20PresExRecord.STATE_ABANDONED
        if reason:
            self.error_msg = reason

        try:
            await self.save(
                session,
                reason=reason,
                log_params=log_params,
                log_override=log_override,
            )
        except StorageError as err:
            LOGGER.exception(err)

    # Override
    async def emit_event(self, session: ProfileSession, payload: Optional[Any] = None):
        """Emit an event.

        Args:
            session: The profile session to use
            payload: The event payload
        """

        if not self.RECORD_TOPIC:
            return

        if self.state:
            topic = f"{self.EVENT_NAMESPACE}::{self.RECORD_TOPIC}::{self.state}"
        else:
            topic = f"{self.EVENT_NAMESPACE}::{self.RECORD_TOPIC}"

        # serialize payload before checking for webhook contents
        if not payload:
            payload = self.serialize()
        if not session.profile.settings.get("debug.webhooks"):
            payload = V20PresExRecordWebhook(**payload)
            payload = payload.__dict__

        await session.profile.notify(topic, payload)

    @property
    def record_value(self) -> Mapping:
        """Accessor for the JSON record value generated for this credential exchange."""
        return {
            **{
                prop: getattr(self, prop)
                for prop in (
                    "connection_id",
                    "initiator",
                    "role",
                    "state",
                    "verified",
                    "verified_msgs",
                    "auto_present",
                    "auto_verify",
                    "error_msg",
                    "trace",
                    "auto_remove",
                )
            },
            **{
                prop: getattr(self, f"_{prop}").ser
                for prop in (
                    "pres_proposal",
                    "pres_request",
                    "pres",
                )
                if getattr(self, prop) is not None
            },
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)

    def get_ac_proof_request(self):
        """Retrieve Indy Proof request from record."""
        proof_request = self.pres_request.attachment(V20PresFormat.Format.INDY)
        # If indy filter fails try anoncreds filter format. This is for a
        # non-anoncreds agent that gets a anoncreds format proof request and
        # should removed when indy format is fully retired.
        if not proof_request:
            proof_request = self.pres_request.attachment(V20PresFormat.Format.ANONCREDS)

        if not proof_request:
            raise ValueError("No AnonCreds proof request on this record")

        return proof_request


class V20PresExRecordSchema(BaseExchangeSchema):
    """Schema for de/serialization of v2.0 presentation exchange records."""

    class Meta:
        """V20PresExRecordSchema metadata."""

        model_class = V20PresExRecord

    pres_ex_id = fields.Str(
        required=False,
        metadata={
            "description": "Presentation exchange identifier",
            "example": UUID4_EXAMPLE,
        },
    )
    connection_id = fields.Str(
        required=False,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )
    thread_id = fields.Str(
        required=False,
        metadata={"description": "Thread identifier", "example": UUID4_EXAMPLE},
    )
    initiator = fields.Str(
        required=False,
        validate=validate.OneOf(
            V20PresExRecord.get_attributes_by_prefix("INITIATOR_", walk_mro=False)
        ),
        metadata={
            "description": "Present-proof exchange initiator: self or external",
            "example": V20PresExRecord.INITIATOR_SELF,
        },
    )
    role = fields.Str(
        required=False,
        validate=validate.OneOf(
            V20PresExRecord.get_attributes_by_prefix("ROLE_", walk_mro=False)
        ),
        metadata={
            "description": "Present-proof exchange role: prover or verifier",
            "example": V20PresExRecord.ROLE_PROVER,
        },
    )
    state = fields.Str(
        required=False,
        validate=validate.OneOf(
            V20PresExRecord.get_attributes_by_prefix("STATE_", walk_mro=True)
        ),
        metadata={"description": "Present-proof exchange state"},
    )
    pres_proposal = fields.Nested(
        V20PresProposalSchema(),
        required=False,
        metadata={"description": "Presentation proposal message"},
    )
    pres_request = fields.Nested(
        V20PresRequestSchema(),
        required=False,
        metadata={"description": "Presentation request message"},
    )
    pres = fields.Nested(
        V20PresSchema(),
        required=False,
        metadata={"description": "Presentation message"},
    )
    by_format = fields.Nested(
        Schema.from_dict(
            {
                "pres_proposal": fields.Dict(required=False),
                "pres_request": fields.Dict(required=False),
                "pres": fields.Dict(required=False),
            },
            name="V20PresExRecordByFormatSchema",
        ),
        required=False,
        dump_only=True,
        metadata={
            "description": (
                "Attachment content by format for proposal, request, and presentation"
            )
        },
    )
    verified = fields.Str(
        required=False,
        validate=validate.OneOf(["true", "false"]),
        metadata={
            "description": "Whether presentation is verified: 'true' or 'false'",
            "example": "true",
        },
    )
    verified_msgs = fields.List(
        fields.Str(
            required=False,
            metadata={"description": "Proof verification warning or error information"},
        ),
        required=False,
    )
    auto_present = fields.Bool(
        required=False,
        metadata={
            "description": "Prover choice to auto-present proof as verifier requests",
            "example": False,
        },
    )
    auto_verify = fields.Bool(
        required=False,
        metadata={"description": "Verifier choice to auto-verify proof presentation"},
    )
    error_msg = fields.Str(
        required=False,
        metadata={"description": "Error message", "example": "Invalid structure"},
    )
    auto_remove = fields.Bool(
        required=False,
        dump_default=True,
        metadata={
            "description": (
                "Verifier choice to remove this presentation exchange record when"
                " complete"
            ),
            "example": False,
        },
    )
