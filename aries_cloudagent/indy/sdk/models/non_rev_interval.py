"""Indy non-revocation interval."""

from time import time

from marshmallow import EXCLUDE, fields

from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.valid import INT_EPOCH


class IndyNonRevocationInterval(BaseModel):
    """Indy non-revocation interval."""

    class Meta:
        """NonRevocationInterval metadata."""

        schema_class = "IndyNonRevocationIntervalSchema"

    def __init__(self, fro: int = None, to: int = None, **kwargs):
        """Initialize non-revocation interval.

        Args:
            fro: earliest time of interest
            to: latest time of interest

        """
        super().__init__(**kwargs)
        self.fro = fro
        self.to = to

    def covers(self, timestamp: int = None) -> bool:
        """Whether input timestamp (default now) lies within non-revocation interval.

        Args:
            timestamp: time of interest

        Returns:
            whether input time satisfies non-revocation interval

        """
        timestamp = timestamp or int(time())
        return (self.fro or 0) <= timestamp <= (self.to or timestamp)

    def timestamp(self) -> bool:
        """Return a timestamp that the non-revocation interval covers."""
        return self.to or self.fro or int(time())


class IndyNonRevocationIntervalSchema(BaseModelSchema):
    """Schema to allow serialization/deserialization of non-revocation intervals."""

    class Meta:
        """IndyNonRevocationIntervalSchema metadata."""

        model_class = IndyNonRevocationInterval
        unknown = EXCLUDE

    fro = fields.Int(
        required=False,
        description="Earliest time of interest in non-revocation interval",
        data_key="from",
        strict=True,
        **INT_EPOCH
    )
    to = fields.Int(
        required=False,
        description="Latest time of interest in non-revocation interval",
        strict=True,
        **INT_EPOCH
    )
