"""Test Problem Report Message."""
import pytest

from unittest import mock, TestCase

from ......messaging.models.base import BaseModelError

from ..problem_report import (
    CMProblemReport,
    CMProblemReportSchema,
    ProblemReportReason,
    ValidationError,
)


class TestCMProblemReportMessage(TestCase):
    """Test problem report."""

    def setUp(self):
        self.problem_report = CMProblemReport(
            description={
                "en": "Insufficient credit",
                "code": ProblemReportReason.MEDIATION_NOT_GRANTED.value,
            }
        )

    def test_make_model(self):
        """Make problem report model."""
        data = self.problem_report.serialize()
        model_instance = CMProblemReport.deserialize(data)
        assert isinstance(model_instance, CMProblemReport)

        model_instance.description["code"] = "extraneous code"
        with pytest.raises(BaseModelError):
            CMProblemReport.deserialize(model_instance)

    def test_validate_x(self):
        """Exercise validation requirements."""
        schema = CMProblemReportSchema()
        with pytest.raises(ValidationError):
            schema.validate_fields({})
