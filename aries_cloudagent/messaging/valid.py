"""Validators for schema fields."""

import json

from datetime import datetime
import re

from base58 import alphabet
from marshmallow.validate import OneOf, Range, Regexp, Validator
from marshmallow.exceptions import ValidationError
from marshmallow.fields import Field

from .util import epoch_to_str

from ..ledger.endpoint_type import EndpointType as EndpointTypeEnum
from ..revocation.models.revocation_registry import RevocationRegistry
from ..wallet.did_posture import DIDPosture as DIDPostureEnum

B58 = alphabet if isinstance(alphabet, str) else alphabet.decode("ascii")


class StrOrDictField(Field):
    """URI or Dict field for Marshmallow."""

    def _serialize(self, value, attr, obj, **kwargs):
        return value

    def _deserialize(self, value, attr, data, **kwargs):
        if isinstance(value, (str, dict)):
            return value
        else:
            raise ValidationError("Field should be str or dict")


class DictOrDictListField(Field):
    """Dict or Dict List field for Marshmallow."""

    def _serialize(self, value, attr, obj, **kwargs):
        return value

    def _deserialize(self, value, attr, data, **kwargs):
        # dict
        if isinstance(value, dict):
            return value
        # list of dicts
        elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
            return value
        else:
            raise ValidationError("Field should be dict or list of dicts")


class UriOrDictField(StrOrDictField):
    """URI or Dict field for Marshmallow."""

    def __init__(self, *args, **kwargs):
        """Initialize new UriOrDictField instance."""
        super().__init__(*args, **kwargs)

        # Insert validation into self.validators so that multiple errors can be stored.
        self.validators.insert(0, self._uri_validator)

    def _uri_validator(self, value):
        # Check if URI when
        if isinstance(value, str):
            return Uri()(value)


class IntEpoch(Range):
    """Validate value against (integer) epoch format."""

    EXAMPLE = int(datetime.now().timestamp())

    def __init__(self):
        """Initializer."""

        super().__init__(  # use u64 for indy-sdk compatibility
            min=0,
            max=18446744073709551615,
            error="Value {input} is not a valid integer epoch time",
        )


class WholeNumber(Range):
    """Validate value as non-negative integer."""

    EXAMPLE = 0

    def __init__(self):
        """Initializer."""

        super().__init__(min=0, error="Value {input} is not a non-negative integer")

    def __call__(self, value):
        """Validate input value."""

        if type(value) != int:
            raise ValidationError("Value {input} is not a valid whole number")
        super().__call__(value)


class NumericStrWhole(Regexp):
    """Validate value against whole number numeric string."""

    EXAMPLE = "0"
    PATTERN = r"^[0-9]*$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            NumericStrWhole.PATTERN,
            error="Value {input} is not a non-negative numeric string",
        )


class NaturalNumber(Range):
    """Validate value as positive integer."""

    EXAMPLE = 10

    def __init__(self):
        """Initializer."""

        super().__init__(min=1, error="Value {input} is not a positive integer")

    def __call__(self, value):
        """Validate input value."""

        if type(value) != int:
            raise ValidationError("Value {input} is not a valid natural number")
        super().__call__(value)


class NumericStrNatural(Regexp):
    """Validate value against natural number numeric string."""

    EXAMPLE = "1"
    PATTERN = r"^[1-9][0-9]*$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            NumericStrNatural.PATTERN,
            error="Value {input} is not a positive numeric string",
        )


class IndyRevRegSize(Range):
    """Validate value as indy revocation registry size."""

    EXAMPLE = 1000

    def __init__(self):
        """Initializer."""

        super().__init__(
            min=RevocationRegistry.MIN_SIZE,
            max=RevocationRegistry.MAX_SIZE,
            error=(
                "Value {input} must be an integer between "
                f"{RevocationRegistry.MIN_SIZE} and "
                f"{RevocationRegistry.MAX_SIZE} inclusively"
            ),
        )

    def __call__(self, value):
        """Validate input value."""

        if type(value) != int:
            raise ValidationError(
                "Value {input} must be an integer between "
                f"{RevocationRegistry.MIN_SIZE} and "
                f"{RevocationRegistry.MAX_SIZE} inclusively"
            )
        super().__call__(value)


class JWSHeaderKid(Regexp):
    """Validate value against JWS header kid."""

    EXAMPLE = "did:sov:LjgpST2rjsoxYegQDRm7EL#keys-4"
    PATTERN = rf"^did:(?:key:z[{B58}]+|sov:[{B58}]{{21,22}}(;.*)?(\?.*)?#.+)$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            JWSHeaderKid.PATTERN,
            error="Value {input} is neither in W3C did:key nor DID URL format",
        )


class JSONWebToken(Regexp):
    """Validate JSON Web Token."""

    EXAMPLE = (
        "eyJhbGciOiJFZERTQSJ9."
        "eyJhIjogIjAifQ."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    PATTERN = r"^[-_a-zA-Z0-9]*\.[-_a-zA-Z0-9]*\.[-_a-zA-Z0-9]*$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            JSONWebToken.PATTERN,
            error="Value {input} is not a valid JSON Web token",
        )


class GenericDID(Regexp):
    """Validate value against DID specification."""

    EXAMPLE = "did:indy:idu:WgWxqztrNooG92RXvxSTWv"
    PATTERN = r"^did:([a-z0-9]+):((?:[a-zA-Z0-9._-]*:)*[a-zA-Z0-9._-]+)"

    def __init__(self):
        """Initializer."""

        super().__init__(
            GenericDID.PATTERN, error="Value {input} is not in W3C did format"
        )


class DIDKey(Regexp):
    """Validate value against DID key specification."""

    EXAMPLE = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
    PATTERN = rf"^did:key:z[{B58}]+$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            DIDKey.PATTERN, error="Value {input} is not in W3C did:key format"
        )


class DIDPosture(OneOf):
    """Validate value against defined DID postures."""

    EXAMPLE = DIDPostureEnum.WALLET_ONLY.moniker

    def __init__(self):
        """Initializer."""

        super().__init__(
            choices=[did_posture.moniker for did_posture in DIDPostureEnum],
            error="Value {input} must be one of {choices}",
        )


class IndyDID(Regexp):
    """Validate value against indy DID."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv"
    PATTERN = rf"^(did:sov:)?[{B58}]{{21,22}}$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyDID.PATTERN,
            error="Value {input} is not an indy decentralized identifier (DID)",
        )


class IndyRawPublicKey(Regexp):
    """Validate value against indy (Ed25519VerificationKey2018) raw public key."""

    EXAMPLE = "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    PATTERN = rf"^[{B58}]{{43,44}}$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyRawPublicKey.PATTERN,
            error="Value {input} is not a raw Ed25519VerificationKey2018 key",
        )


class IndyCredDefId(Regexp):
    """Validate value against indy credential definition identifier specification."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv:3:CL:20:tag"
    PATTERN = (
        rf"^([{B58}]{{21,22}})"  # issuer DID
        f":3"  # cred def id marker
        f":CL"  # sig alg
        rf":(([1-9][0-9]*)|([{B58}]{{21,22}}:2:.+:[0-9.]+))"  # schema txn / id
        f":(.+)?$"  # tag
    )

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyCredDefId.PATTERN,
            error="Value {input} is not an indy credential definition identifier",
        )


class IndyVersion(Regexp):
    """Validate value against indy version specification."""

    EXAMPLE = "1.0"
    PATTERN = r"^[0-9.]+$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyVersion.PATTERN,
            error="Value {input} is not an indy version (use only digits and '.')",
        )


class IndySchemaId(Regexp):
    """Validate value against indy schema identifier specification."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv:2:schema_name:1.0"
    PATTERN = rf"^[{B58}]{{21,22}}:2:.+:[0-9.]+$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndySchemaId.PATTERN,
            error="Value {input} is not an indy schema identifier",
        )


class IndyRevRegId(Regexp):
    """Validate value against indy revocation registry identifier specification."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv:4:WgWxqztrNooG92RXvxSTWv:3:CL:20:tag:CL_ACCUM:0"
    PATTERN = (
        rf"^([{B58}]{{21,22}}):4:"
        rf"([{B58}]{{21,22}}):3:"
        rf"CL:(([1-9][0-9]*)|([{B58}]{{21,22}}:2:.+:[0-9.]+))(:.+)?:"
        rf"CL_ACCUM:(.+$)"
    )

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyRevRegId.PATTERN,
            error="Value {input} is not an indy revocation registry identifier",
        )


class IndyCredRevId(Regexp):
    """Validate value against indy credential revocation identifier specification."""

    EXAMPLE = "12345"
    PATTERN = r"^[1-9][0-9]*$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyCredRevId.PATTERN,
            error="Value {input} is not an indy credential revocation identifier",
        )


class IndyPredicate(OneOf):
    """Validate value against indy predicate."""

    EXAMPLE = ">="

    def __init__(self):
        """Initializer."""

        super().__init__(
            choices=["<", "<=", ">=", ">"],
            error="Value {input} must be one of {choices}",
        )


class IndyISO8601DateTime(Regexp):
    """Validate value against ISO 8601 datetime format, indy profile."""

    EXAMPLE = epoch_to_str(int(datetime.now().timestamp()))
    PATTERN = (
        r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d"
        r"(?:\:(?:\d\d(?:\.\d{1,6})?))?(?:[+-]\d\d:?\d\d|Z|)$"
    )

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyISO8601DateTime.PATTERN,
            error="Value {input} is not a date in valid format",
        )


class RFC3339DateTime(Regexp):
    """Validate value against RFC3339 datetime format."""

    EXAMPLE = "2010-01-01T19:23:24Z"
    PATTERN = (
        r"^([0-9]{4})-([0-9]{2})-([0-9]{2})([Tt ]([0-9]{2}):([0-9]{2}):"
        r"([0-9]{2})(\.[0-9]+)?)?(([Zz]|([+-])([0-9]{2}):([0-9]{2})))?$"
    )

    def __init__(self):
        """Initializer."""

        super().__init__(
            RFC3339DateTime.PATTERN,
            error="Value {input} is not a date in valid format",
        )


class IndyWQL(Regexp):  # using Regexp brings in nice visual validator cue
    """Validate value as potential WQL query."""

    EXAMPLE = json.dumps({"attr::name::value": "Alex"})
    PATTERN = r"^{.*}$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyWQL.PATTERN,
            error="Value {input} is not a valid WQL query",
        )

    def __call__(self, value):
        """Validate input value."""

        super().__call__(value or "")
        message = f"Value {value} is not a valid WQL query"

        try:
            json.loads(value)
        except (json.JSONDecodeError, TypeError):
            raise ValidationError(message)

        return value


class IndyExtraWQL(Regexp):  # using Regexp brings in nice visual validator cue
    """Validate value as potential extra WQL query in cred search for proof req."""

    EXAMPLE = json.dumps({"0_drink_uuid": {"attr::drink::value": "martini"}})
    PATTERN = r'^{\s*".*?"\s*:\s*{.*?}\s*(,\s*".*?"\s*:\s*{.*?}\s*)*\s*}$'

    def __init__(self):
        """Initializer."""

        super().__init__(
            IndyExtraWQL.PATTERN,
            error="Value {input} is not a valid extra WQL query",
        )

    def __call__(self, value):
        """Validate input value."""

        super().__call__(value or "")
        message = f"Value {value} is not a valid extra WQL query"

        try:
            json.loads(value)
        except (json.JSONDecodeError, TypeError):
            raise ValidationError(message)

        return value


class Base64(Regexp):
    """Validate base64 value."""

    EXAMPLE = "ey4uLn0="
    PATTERN = r"^[a-zA-Z0-9+/]*={0,2}$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            Base64.PATTERN,
            error="Value {input} is not a valid base64 encoding",
        )


class Base64URL(Regexp):
    """Validate base64 value."""

    EXAMPLE = "ey4uLn0="
    PATTERN = r"^[-_a-zA-Z0-9]*={0,2}$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            Base64URL.PATTERN,
            error="Value {input} is not a valid base64url encoding",
        )


class Base64URLNoPad(Regexp):
    """Validate base64 value."""

    EXAMPLE = "ey4uLn0"
    PATTERN = r"^[-_a-zA-Z0-9]*$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            Base64URLNoPad.PATTERN,
            error="Value {input} is not a valid unpadded base64url encoding",
        )


class SHA256Hash(Regexp):
    """Validate (binhex-encoded) SHA256 value."""

    EXAMPLE = "617a48c7c8afe0521efdc03e5bb0ad9e655893e6b4b51f0e794d70fba132aacb"
    PATTERN = r"^[a-fA-F0-9+/]{64}$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            SHA256Hash.PATTERN,
            error="Value {input} is not a valid (binhex-encoded) SHA-256 hash",
        )


class Base58SHA256Hash(Regexp):
    """Validate value against base58 encoding of SHA-256 hash."""

    EXAMPLE = "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    PATTERN = rf"^[{B58}]{{43,44}}$"

    def __init__(self):
        """Initializer."""

        super().__init__(
            Base58SHA256Hash.PATTERN,
            error="Value {input} is not a base58 encoding of a SHA-256 hash",
        )


class UUIDFour(Regexp):
    """Validate UUID4: 8-4-4-4-12 hex digits, the 13th of which being 4."""

    EXAMPLE = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
    PATTERN = (
        r"[a-fA-F0-9]{8}-"
        r"[a-fA-F0-9]{4}-"
        r"4[a-fA-F0-9]{3}-"
        r"[a-fA-F0-9]{4}-"
        r"[a-fA-F0-9]{12}"
    )

    def __init__(self):
        """Initializer."""

        super().__init__(
            UUIDFour.PATTERN,
            error="Value {input} is not UUID4 (8-4-4-4-12 hex digits with digit#13=4)",
        )


class Uri(Regexp):
    """Validate value against URI on any scheme."""

    EXAMPLE = "https://www.w3.org/2018/credentials/v1"
    PATTERN = r"\w+:(\/?\/?)[^\s]+"

    def __init__(self):
        """Initializer."""
        super().__init__(Uri.PATTERN, error="Value {input} is not URI")


class Endpoint(Regexp):  # using Regexp brings in nice visual validator cue
    """Validate value against endpoint URL on any scheme."""

    EXAMPLE = "https://myhost:8021"
    PATTERN = (
        r"^[A-Za-z0-9\.\-\+]+:"  # scheme
        r"//([A-Za-z0-9][.A-Za-z0-9-]+[A-Za-z0-9])+"  # host
        r"(:[1-9][0-9]*)?"  # port
        r"(/[^?&#]+)?$"  # path
    )

    def __init__(self):
        """Initializer."""

        super().__init__(
            Endpoint.PATTERN,
            error="Value {input} is not a valid endpoint",
        )


class EndpointType(OneOf):
    """Validate value against allowed endpoint/service types."""

    EXAMPLE = EndpointTypeEnum.ENDPOINT.w3c

    def __init__(self):
        """Initializer."""

        super().__init__(
            choices=[e.w3c for e in EndpointTypeEnum],
            error="Value {input} must be one of {choices}",
        )


class CredentialType(Validator):
    """Credential Type."""

    CREDENTIAL_TYPE = "VerifiableCredential"
    EXAMPLE = [CREDENTIAL_TYPE, "AlumniCredential"]

    def __init__(self) -> None:
        """Initializer."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        length = len(value)
        if length < 1 or CredentialType.CREDENTIAL_TYPE not in value:
            raise ValidationError(f"type must include {CredentialType.CREDENTIAL_TYPE}")

        return value


class CredentialContext(Validator):
    """Credential Context."""

    FIRST_CONTEXT = "https://www.w3.org/2018/credentials/v1"
    EXAMPLE = [FIRST_CONTEXT, "https://www.w3.org/2018/credentials/examples/v1"]

    def __init__(self) -> None:
        """Initializer."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        length = len(value)

        if length < 1 or value[0] != CredentialContext.FIRST_CONTEXT:
            raise ValidationError(
                f"First context must be {CredentialContext.FIRST_CONTEXT}"
            )

        return value


class CredentialSubject(Validator):
    """Credential subject."""

    EXAMPLE = {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": {"id": "did:example:c276e12ec21ebfeb1f712ebc6f1"},
    }

    def __init__(self) -> None:
        """Initializer."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        subjects = value if isinstance(value, list) else [value]

        for subject in subjects:
            if "id" in subject:
                uri_validator = Uri()
                try:
                    uri_validator(value["id"])
                except ValidationError:
                    raise ValidationError(
                        f"credential subject id {value[0]} must be URI"
                    )

        return value


class IndyOrKeyDID(Regexp):
    """Indy or Key DID class."""

    PATTERN = re.compile("|".join([DIDKey.PATTERN, IndyDID.PATTERN]))
    EXAMPLE = IndyDID.EXAMPLE

    def __init__(
        self,
    ):
        """Initializer."""
        super().__init__(
            IndyOrKeyDID.PATTERN,
            error="Value {input} is not in did:key or indy did format",
        )


class IndyOrGenericDID(Regexp):
    """Indy or Generic DID class."""

    PATTERN = re.compile("|".join([GenericDID.PATTERN, IndyDID.PATTERN]))
    EXAMPLE = IndyDID.EXAMPLE

    def __init__(
        self,
    ):
        """Initializer."""
        super().__init__(
            IndyOrGenericDID.PATTERN,
            error="Value {input} is not in generic did or indy did format",
        )


# Instances for marshmallow schema specification
INT_EPOCH = {"validate": IntEpoch(), "example": IntEpoch.EXAMPLE}
WHOLE_NUM = {"validate": WholeNumber(), "example": WholeNumber.EXAMPLE}
NUM_STR_WHOLE = {"validate": NumericStrWhole(), "example": NumericStrWhole.EXAMPLE}
NATURAL_NUM = {"validate": NaturalNumber(), "example": NaturalNumber.EXAMPLE}
NUM_STR_NATURAL = {
    "validate": NumericStrNatural(),
    "example": NumericStrNatural.EXAMPLE,
}
INDY_REV_REG_SIZE = {"validate": IndyRevRegSize(), "example": IndyRevRegSize.EXAMPLE}
JWS_HEADER_KID = {"validate": JWSHeaderKid(), "example": JWSHeaderKid.EXAMPLE}
JWT = {"validate": JSONWebToken(), "example": JSONWebToken.EXAMPLE}
GENERIC_DID = {"validate": GenericDID(), "example": GenericDID.EXAMPLE}
DID_KEY = {"validate": DIDKey(), "example": DIDKey.EXAMPLE}
DID_POSTURE = {"validate": DIDPosture(), "example": DIDPosture.EXAMPLE}
INDY_DID = {"validate": IndyDID(), "example": IndyDID.EXAMPLE}
INDY_RAW_PUBLIC_KEY = {
    "validate": IndyRawPublicKey(),
    "example": IndyRawPublicKey.EXAMPLE,
}
INDY_SCHEMA_ID = {"validate": IndySchemaId(), "example": IndySchemaId.EXAMPLE}
INDY_CRED_DEF_ID = {"validate": IndyCredDefId(), "example": IndyCredDefId.EXAMPLE}
INDY_REV_REG_ID = {"validate": IndyRevRegId(), "example": IndyRevRegId.EXAMPLE}
INDY_CRED_REV_ID = {"validate": IndyCredRevId(), "example": IndyCredRevId.EXAMPLE}
INDY_VERSION = {"validate": IndyVersion(), "example": IndyVersion.EXAMPLE}
INDY_PREDICATE = {"validate": IndyPredicate(), "example": IndyPredicate.EXAMPLE}
INDY_ISO8601_DATETIME = {
    "validate": IndyISO8601DateTime(),
    "example": IndyISO8601DateTime.EXAMPLE,
}
RFC3339_DATETIME = {"validate": RFC3339DateTime(), "example": RFC3339DateTime.EXAMPLE}
INDY_WQL = {"validate": IndyWQL(), "example": IndyWQL.EXAMPLE}
INDY_EXTRA_WQL = {"validate": IndyExtraWQL(), "example": IndyExtraWQL.EXAMPLE}
BASE64 = {"validate": Base64(), "example": Base64.EXAMPLE}
BASE64URL = {"validate": Base64URL(), "example": Base64URL.EXAMPLE}
BASE64URL_NO_PAD = {"validate": Base64URLNoPad(), "example": Base64URLNoPad.EXAMPLE}
SHA256 = {"validate": SHA256Hash(), "example": SHA256Hash.EXAMPLE}
BASE58_SHA256_HASH = {
    "validate": Base58SHA256Hash(),
    "example": Base58SHA256Hash.EXAMPLE,
}
UUID4 = {"validate": UUIDFour(), "example": UUIDFour.EXAMPLE}
ENDPOINT = {"validate": Endpoint(), "example": Endpoint.EXAMPLE}
ENDPOINT_TYPE = {"validate": EndpointType(), "example": EndpointType.EXAMPLE}
CREDENTIAL_TYPE = {"validate": CredentialType(), "example": CredentialType.EXAMPLE}
CREDENTIAL_CONTEXT = {
    "validate": CredentialContext(),
    "example": CredentialContext.EXAMPLE,
}
URI = {"validate": Uri(), "example": Uri.EXAMPLE}
CREDENTIAL_SUBJECT = {
    "validate": CredentialSubject(),
    "example": CredentialSubject.EXAMPLE,
}
INDY_OR_KEY_DID = {
    "validate": IndyOrKeyDID(),
    "example": IndyOrKeyDID.EXAMPLE,
}
INDY_OR_GENERIC_DID = {
    "validate": IndyOrGenericDID(),
    "example": IndyOrGenericDID.EXAMPLE,
}
