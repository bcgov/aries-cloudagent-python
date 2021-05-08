"""Represents a coordinate-mediation problem report message."""

from enum import Enum

from marshmallow import EXCLUDE, ValidationError, validates_schema

from ....problem_report.v1_0.message import ProblemReport, ProblemReportSchema

from ..message_types import PROBLEM_REPORT, PROTOCOL_PACKAGE

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers" ".problem_report_handler.CMProblemReportHandler"
)


class ProblemReportReason(Enum):
    """Supported reason codes."""

    MEDIATION_NOT_GRANTED = "mediation_not_granted"
    MEDIATION_REQUEST_REPEAT = "request_already_exists_from_connection"


class CMProblemReport(ProblemReport):
    """Base class representing a coordinate mediation problem report message."""

    class Meta:
        """CMProblemReport metadata."""

        handler_class = HANDLER_CLASS
        message_type = PROBLEM_REPORT
        schema_class = "CMProblemReportSchema"

    def __init__(self, *args, **kwargs):
        """Initialize a ProblemReport message instance."""
        super().__init__(*args, **kwargs)


class CMProblemReportSchema(ProblemReportSchema):
    """Schema for ProblemReport base class."""

    class Meta:
        """Metadata for problem report schema."""

        model_class = CMProblemReport
        unknown = EXCLUDE

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate schema fields."""

        if data.get("description", {}).get("code", "") not in [
            prr.value for prr in ProblemReportReason
        ]:
            raise ValidationError(
                "Value for description.code must be one of "
                f"{[prr.value for prr in ProblemReportReason]}"
            )
