"""Common code for messaging models."""

from typing import Mapping, Union

from .base import BaseModel


def to_serial(obj: Union[BaseModel, Mapping]) -> Mapping:
    """Serialize input object if need be."""
    return obj.serialize() if isinstance(obj, BaseModel) else obj
