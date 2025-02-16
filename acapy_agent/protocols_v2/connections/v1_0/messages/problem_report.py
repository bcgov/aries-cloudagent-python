"""Represents a connection problem report message."""

import logging
from enum import Enum
from typing import Optional

from marshmallow import EXCLUDE, ValidationError, validates_schema

from .....protocols.problem_report.v1_0.message import ProblemReport, ProblemReportSchema
from ..message_types import PROBLEM_REPORT

HANDLER_CLASS = (
    "acapy_agent.protocols.connections.v1_0.handlers."
    "problem_report_handler.ConnectionProblemReportHandler"
)

LOGGER = logging.getLogger(__name__)


class ProblemReportReason(Enum):
    """Supported reason codes."""

    INVITATION_NOT_ACCEPTED = "invitation_not_accepted"
    REQUEST_NOT_ACCEPTED = "request_not_accepted"
    REQUEST_PROCESSING_ERROR = "request_processing_error"
    RESPONSE_NOT_ACCEPTED = "response_not_accepted"
    RESPONSE_PROCESSING_ERROR = "response_processing_error"
    MISSING_RECIPIENT_KEYS = "invitation_missing_recipient_keys"
    MISSING_ENDPOINT = "invitation_missing_endpoint"


class ConnectionProblemReport(ProblemReport):
    """Base class representing a connection problem report message."""

    class Meta:
        """Connection problem report metadata."""

        handler_class = HANDLER_CLASS
        message_type = PROBLEM_REPORT
        schema_class = "ConnectionProblemReportSchema"

    def __init__(
        self,
        *,
        problem_code: Optional[str] = None,
        explain: Optional[str] = None,
        **kwargs,
    ):
        """Initialize a ProblemReport message instance.

        Args:
            problem_code: The standard error identifier
            explain: The localized error explanation
            kwargs: Additional keyword arguments
        """
        super().__init__(**kwargs)
        self.explain = explain
        self.problem_code = problem_code


class ConnectionProblemReportSchema(ProblemReportSchema):
    """Schema for ConnectionProblemReport base class."""

    class Meta:
        """Metadata for connection problem report schema."""

        model_class = ConnectionProblemReport
        unknown = EXCLUDE

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate schema fields."""

        if not data.get("description", {}).get("code", ""):
            raise ValidationError("Value for description.code must be present")
        elif data.get("description", {}).get("code", "") not in [
            prr.value for prr in ProblemReportReason
        ]:
            locales = list(data.get("description").keys())
            locales.remove("code")
            LOGGER.warning(
                "Unexpected error code received.\n"
                f"Code: {data.get('description').get('code')}, "
                f"Description: {data.get('description').get(locales[0])}"
            )
