"""DIDComm prefix management."""
import re

from enum import Enum
from os import environ
from typing import Mapping

QUALIFIED = re.compile(r"^[a-zA-Z\-\+]+:.+")


def qualify(msg_type: str, prefix: str):
    """Qualify a message type with a prefix, if unqualified."""

    return msg_type if QUALIFIED.match(msg_type or "") else f"{prefix}/{msg_type}"


class DIDCommPrefix(Enum):
    """Enum for DIDComm Prefix, old or new style, per Aries RFC 384."""

    NEW = "https://didcomm.org"
    OLD = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec"

    @staticmethod
    def set(settings: Mapping):
        """Set current DIDComm prefix value in environment."""

        environ["DIDCOMM_PREFIX"] = (
            DIDCommPrefix.NEW.value
            if settings.get("aip_version", 1) >= 2
            else DIDCommPrefix.OLD.value
        )

    def qualify(self, msg_type: str = None) -> str:
        """Qualify input message type with prefix and separator."""

        return qualify(msg_type, self.value)

    @classmethod
    def qualify_all(cls, messages: dict) -> dict:
        """Apply all known prefixes to a dictionary of message types."""

        result = {}
        for pfx in cls:
            for k, v in messages.items():
                result[qualify(k, pfx.value)] = v
        return result

    @staticmethod
    def qualify_current(slug: str = None) -> str:
        """Qualify input slug with prefix currently in effect and separator."""

        return qualify(slug, environ.get("DIDCOMM_PREFIX", DIDCommPrefix.OLD.value))

    @staticmethod
    def unqualify(qual: str) -> str:
        """Strip prefix and separator from input, if present, and return result."""
        for pfx in DIDCommPrefix:
            if (qual or "").startswith(f"{pfx.value}/"):
                return qual.split(f"{pfx.value}/")[1]

        return qual
