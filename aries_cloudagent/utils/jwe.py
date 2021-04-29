"""JSON Web Encryption utilities."""

import json

from collections import OrderedDict
from typing import Any, Iterable, List, Mapping, Optional, Union

from marshmallow import fields, Schema, ValidationError

from ..wallet.util import b64_to_bytes, bytes_to_b64

IDENT_ENC_KEY = "encrypted_key"
IDENT_HEADER = "header"
IDENT_PROTECTED = "protected"
IDENT_RECIPIENTS = "recipients"


def b64url(value: Union[bytes, str]) -> str:
    """Encode a string or bytes value as unpadded base64-URL."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return bytes_to_b64(value, urlsafe=True, pad=False)


def from_b64url(value: str) -> bytes:
    """Decode an unpadded base64-URL value."""
    return b64_to_bytes(value, urlsafe=True)


class B64Value(fields.Str):
    """A marshmallow-compatible wrapper for base64-URL values."""

    def _serialize(self, value, attr, obj, **kwargs) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, bytes):
            return TypeError("Expected bytes")
        return b64url(value)

    def _deserialize(self, value, attr, data, **kwargs) -> Any:
        value = super()._deserialize(value, attr, data, **kwargs)
        return from_b64url(value)


class JweSchema(Schema):
    """JWE envelope schema."""

    protected = fields.Str(required=True)
    unprotected = fields.Dict(required=False)
    ciphertext = B64Value(required=True)
    iv = B64Value(required=True)
    tag = B64Value(required=True)
    aad = B64Value(required=False)
    # flattened:
    header = fields.Dict(required=False)
    encrypted_key = B64Value(required=False)


class JweRecipientSchema(Schema):
    """JWE recipient schema."""

    encrypted_key = B64Value(required=True)
    header = fields.Dict(many=True, required=False)


class JweRecipient:
    """A single message recipient."""

    def __init__(self, *, encrypted_key: bytes, header: dict = None) -> "JweRecipient":
        """Initialize the JWE recipient."""
        self.encrypted_key = encrypted_key
        self.header = header or {}

    @classmethod
    def deserialize(cls, entry: Mapping[str, Any]) -> "JweRecipient":
        """Deserialize a JWE recipient from a mapping."""
        vals = JweRecipientSchema().load(entry)
        return cls(**vals)

    def serialize(self) -> dict:
        """Serialize the JWE recipient to a mapping."""
        ret = OrderedDict([("encrypted_key", b64url(self.encrypted_key))])
        if self.header:
            ret["header"] = self.header
        return ret


class JweEnvelope:
    """JWE envelope instance."""

    def __init__(
        self,
        *,
        protected: dict = None,
        protected_b64: bytes = None,
        unprotected: dict = None,
        ciphertext: bytes = None,
        iv: bytes = None,
        tag: bytes = None,
        aad: bytes = None,
    ):
        """Initialize a new JWE envelope instance."""
        self.protected = protected
        self.protected_b64 = protected_b64
        self.unprotected = unprotected or OrderedDict()
        self.ciphertext = ciphertext
        self.iv = iv
        self.tag = tag
        self.aad = aad
        self._recipients: List[JweRecipient] = []

    @classmethod
    def from_json(cls, message: Union[bytes, str]) -> "JweEnvelope":
        """Decode a JWE envelope from a JSON string or bytes value."""
        try:
            return cls._deserialize(JweSchema().loads(message))
        except json.JSONDecodeError:
            raise ValidationError("Invalid JWE: not JSON")

    @classmethod
    def deserialize(cls, message: Mapping[str, Any]) -> "JweEnvelope":
        """Deserialize a JWE envelope from a mapping."""
        return cls._deserialize(JweSchema().load(message))

    @classmethod
    def _deserialize(cls, parsed: Mapping[str, Any]) -> "JweEnvelope":
        protected_b64 = parsed[IDENT_PROTECTED]
        try:
            protected: dict = json.loads(from_b64url(protected_b64))
        except json.JSONDecodeError:
            raise ValidationError(
                "Invalid JWE: invalid JSON for protected headers"
            ) from None
        unprotected = parsed.get("unprotected") or dict()
        if protected.keys() & unprotected.keys():
            raise ValidationError("Invalid JWE: duplicate header")

        if IDENT_RECIPIENTS in protected:
            recips = [
                JweRecipient.deserialize(recip)
                for recip in protected.pop(IDENT_RECIPIENTS)
            ]
            if IDENT_ENC_KEY in protected or IDENT_HEADER in protected:
                raise ValidationError("Invalid JWE: flattened form with recipients")
        else:
            if IDENT_ENC_KEY not in protected:
                raise ValidationError("Invalid JWE: no recipients")
            header = protected.pop(IDENT_HEADER) if IDENT_HEADER in protected else None
            recips = [
                JweRecipient(
                    encrypted_key=from_b64url(protected.pop(IDENT_ENC_KEY)),
                    header=header,
                )
            ]

        inst = cls(
            protected=protected,
            protected_b64=protected_b64,
            unprotected=unprotected,
            ciphertext=parsed["ciphertext"],
            iv=parsed.get("iv"),
            tag=parsed["tag"],
            aad=parsed.get("aad"),
        )
        all_h = protected.keys() | unprotected.keys()
        for recip in recips:
            if recip.header and recip.header.keys() & all_h:
                raise ValidationError("Invalid JWE: duplicate header")
            inst.add_recipient(recip)

        return inst

    def serialize(self) -> dict:
        """Serialize the JWE envelope to a mapping."""
        if self.protected_b64 is None:
            raise ValidationError("Missing protected: use set_protected")
        if self.ciphertext is None:
            raise ValidationError("Missing ciphertext for JWE")
        if self.iv is None:
            raise ValidationError("Missing iv (nonce) for JWE")
        if self.tag is None:
            raise ValidationError("Missing tag for JWE")
        env = OrderedDict()
        env["protected"] = self.protected_b64
        if self.unprotected:
            env["unprotected"] = self.unprotected
        env["iv"] = b64url(self.iv)
        env["ciphertext"] = b64url(self.ciphertext)
        env["tag"] = b64url(self.tag)
        if self.aad:
            env["aad"] = b64url(self.aad)
        return env

    def to_json(self) -> str:
        """Serialize the JWE envelope to a JSON string."""
        return json.dumps(self.serialize())

    def add_recipient(self, recip: JweRecipient):
        """Add a recipient to the JWE envelope."""
        self._recipients.append(recip)

    def set_protected(self, protected: Mapping[str, Any], auto_flatten: bool = True):
        """Set the protected headers of the JWE envelope.

        This method must be called after adding the message recipients,
        or with the recipients pre-encoded and added to the headers.
        """
        protected = OrderedDict(protected.items())
        have_recips = IDENT_RECIPIENTS in protected or IDENT_ENC_KEY in protected
        if not have_recips:
            recipients = [recip.serialize() for recip in self._recipients]
            if auto_flatten and len(recipients) == 1:
                protected[IDENT_ENC_KEY] = recipients[0]["encrypted_key"]
                if "header" in recipients[0]:
                    protected[IDENT_HEADER] = recipients[0]["header"]
            elif recipients:
                protected[IDENT_RECIPIENTS] = recipients
            else:
                raise ValidationError("Missing message recipients")
        self.protected_b64 = b64url(json.dumps(protected))

    @property
    def protected_bytes(self) -> bytes:
        """Access the protected data encoded as bytes.

        This value is used in the additional authenticated data when encrypting.
        """
        return (
            self.protected_b64.encode("utf-8")
            if self.protected_b64 is not None
            else None
        )

    def set_payload(self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes = None):
        """Set the payload of the JWE envelope."""
        self.ciphertext = ciphertext
        self.iv = iv
        self.tag = tag
        self.aad = aad

    def recipients(self) -> Iterable[JweRecipient]:
        """Accessor for an iterator over the JWE recipients.

        The headers for each recipient include protected and unprotected headers from the
        outer envelope.
        """
        header = self.protected.copy()
        header.update(self.unprotected)
        for recip in self._recipients:
            if recip.header:
                recip_h = header.copy()
                recip_h.update(recip.header)
                yield JweRecipient(encrypted_key=recip.encrypted_key, header=recip_h)
            else:
                yield JweRecipient(encrypted_key=recip.encrypted_key, header=header)
