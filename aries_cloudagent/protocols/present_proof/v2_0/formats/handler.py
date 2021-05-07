from abc import ABC, abstractclassmethod, abstractmethod
import logging

from typing import Mapping, Tuple, Union

from .....core.error import BaseError
from .....core.profile import Profile
from .....messaging.decorators.attach_decorator import AttachDecorator

from ..messages.pres import V20Pres
from ..messages.pres_ack import V20PresAck
from ..messages.pres_format import V20PresFormat
from ..messages.pres_proposal import V20PresProposal
from ..messages.pres_request import V20PresRequest
from ..message_types import ATTACHMENT_FORMAT
from ..models.pres_exchange import V20PresExRecord

LOGGER = logging.getLogger(__name__)

PresFormatAttachment = Tuple[V20PresFormat, AttachDecorator]


class V20PresFormatError(BaseError):
    """Presentation exchange format error under present-proof protocol v2.0."""


class V20PresFormatHandler(ABC):
    """Base Presentation Exchange Handler."""

    format: V20PresFormat.Format = None

    def __init__(self, profile: Profile):
        """Initialize PresExchange Handler."""
        super().__init__()
        self.profile = profile

    @property
    def profile(self) -> Profile:
        """
        Accessor for the current profile instance.

        Returns:
            The profile instance for this presentation exchange format

        """
        return self._profile

    def get_format_identifier(self, message_type: str) -> str:
        """Get attachment format identifier for format and message combination.

        Args:
            message_type (str): Message type for which to return the format identifier

        Returns:
            str: Issue credential attachment format identifier

        """
        return ATTACHMENT_FORMAT[message_type][self.format.api]

    def get_format_data(self, message_type: str, data: dict) -> PresFormatAttachment:
        """Get presentation format and attachment objects for use in presentation ex messages."""
        if self.format.api == "dif":
            attach = AttachDecorator.data_json(data, ident=self.format.api)
        elif self.format.api == "indy":
            attach = AttachDecorator.data_base64(data, ident=self.format.api)

        return (
            V20PresFormat(
                attach_id=self.format.api,
                format_=self.get_format_identifier(message_type),
            ),
            attach,
        )

    @abstractclassmethod
    def validate_fields(cls, message_type: str, attachment_data: dict) -> None:
        """Validate attachment data for specific message type and format."""
        
    @abstractmethod
    async def create_bound_request(
        self,
        pres_ex_record: V20PresExRecord,
        request_data: dict = None,
    ) -> PresFormatAttachment:
        """Create a presentation request bound to a proposal."""

    @abstractmethod
    async def create_pres(
        self,
        pres_ex_record: V20PresExRecord,
        request_data: dict = None,
    ) -> PresFormatAttachment:
        """Create a presentation."""

    @abstractmethod
    async def receive_pres(
        self, message: V20Pres, pres_ex_record: V20PresExRecord
    ) -> None:
        """Receive a presentation, from message in context on manager creation"""

    @abstractmethod
    async def verify_pres(self, pres_ex_record: V20PresExRecord) -> V20PresExRecord:
        """Verify a presentation."""

    @abstractmethod
    async def create_exchange_for_proposal(
        self,
        pres_ex_record: V20PresExRecord,
        pres_proposal_message: V20PresProposal,
    ) -> None:
        """Create a presentation exchange record for input presentation proposal."""

    @abstractmethod
    async def receive_pres_proposal(
        self,
        pres_ex_record: V20PresExRecord,
        message: V20PresProposal,
    ) -> None:
        """Receive a presentation proposal from message in context on manager creation."""

    @abstractmethod
    async def create_exchange_for_request(
        self,
        pres_ex_record: V20PresExRecord,
        pres_request_message: V20PresRequest,
    ) -> None:
        """Create a presentation exchange record for input presentation request."""
