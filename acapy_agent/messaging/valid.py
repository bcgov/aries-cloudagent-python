"""Validators for schema fields."""

import json
import re

from base58 import alphabet
from marshmallow.exceptions import ValidationError
from marshmallow.fields import Field
from marshmallow.validate import OneOf, Range, Regexp, Validator

from ..ledger.endpoint_type import EndpointType as EndpointTypeEnum
from ..revocation.models.revocation_registry import RevocationRegistry
from ..wallet.did_posture import DIDPosture as DIDPostureEnum
from .util import epoch_to_str

B58 = alphabet if isinstance(alphabet, str) else alphabet.decode("ascii")

EXAMPLE_TIMESTAMP = 1640995199  # 2021-12-31 23:59:59Z


class StrOrDictField(Field):
    """URI or Dict field for Marshmallow."""

    def _deserialize(self, value, attr, data, **kwargs):
        if not isinstance(value, (str, dict)):
            raise ValidationError("Field should be str or dict")
        return super()._deserialize(value, attr, data, **kwargs)


class StrOrNumberField(Field):
    """String or Number field for Marshmallow."""

    def _deserialize(self, value, attr, data, **kwargs):
        if not isinstance(value, (str, float, int)):
            raise ValidationError("Field should be str or int or float")
        return super()._deserialize(value, attr, data, **kwargs)


class DictOrDictListField(Field):
    """Dict or Dict List field for Marshmallow."""

    def _deserialize(self, value, attr, data, **kwargs):
        if not isinstance(value, dict):
            if not isinstance(value, list) or not all(
                isinstance(item, dict) for item in value
            ):
                raise ValidationError("Field should be dict or list of dicts")
        return super()._deserialize(value, attr, data, **kwargs)


class UriOrDictField(StrOrDictField):
    """URI or Dict field for Marshmallow."""

    def _deserialize(self, value, attr, data, **kwargs):
        if isinstance(value, str):
            # Check regex
            Uri()(value)
        return super()._deserialize(value, attr, data, **kwargs)


class IntEpoch(Range):
    """Validate value against (integer) epoch format."""

    EXAMPLE = EXAMPLE_TIMESTAMP

    def __init__(self):
        """Initialize the instance."""

        super().__init__(  # use u64 for indy-sdk compatibility
            min=0,
            max=18446744073709551615,
            error="Value {input} is not a valid integer epoch time",
        )


class WholeNumber(Range):
    """Validate value as non-negative integer."""

    EXAMPLE = 0

    def __init__(self):
        """Initialize the instance."""

        super().__init__(min=0, error="Value {input} is not a non-negative integer")

    def __call__(self, value):
        """Validate input value."""

        if not isinstance(value, int):
            raise ValidationError("Value {input} is not a valid whole number")
        super().__call__(value)


class NumericStrWhole(Regexp):
    """Validate value against whole number numeric string."""

    EXAMPLE = "0"
    PATTERN = r"^[0-9]*$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            NumericStrWhole.PATTERN,
            error="Value {input} is not a non-negative numeric string",
        )


class NumericStrAny(Regexp):
    """Validate value against any number numeric string."""

    EXAMPLE = "-1"
    PATTERN = r"^-?[0-9]*$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            NumericStrAny.PATTERN,
            error="Value {input} is not a numeric string",
        )


class NaturalNumber(Range):
    """Validate value as positive integer."""

    EXAMPLE = 10

    def __init__(self):
        """Initialize the instance."""

        super().__init__(min=1, error="Value {input} is not a positive integer")

    def __call__(self, value):
        """Validate input value."""

        if not isinstance(value, int):
            raise ValidationError("Value {input} is not a valid natural number")
        super().__call__(value)


class NumericStrNatural(Regexp):
    """Validate value against natural number numeric string."""

    EXAMPLE = "1"
    PATTERN = r"^[1-9][0-9]*$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            NumericStrNatural.PATTERN,
            error="Value {input} is not a positive numeric string",
        )


class IndyRevRegSize(Range):
    """Validate value as indy revocation registry size."""

    EXAMPLE = 1000

    def __init__(self):
        """Initialize the instance."""

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

        if not isinstance(value, int):
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
        """Initialize the instance."""

        super().__init__(
            JWSHeaderKid.PATTERN,
            error="Value {input} is neither in W3C did:key nor DID URL format",
        )


class NonSDList(Regexp):
    """Validate NonSD List."""

    EXAMPLE = [
        "name",
        "address",
        "address.street_address",
        "nationalities[1:3]",
    ]
    PATTERN = r"[a-z0-9:\[\]_\.@?\(\)]"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            NonSDList.PATTERN,
            error="Value {input} is not a valid NonSDList",
        )


class JSONWebToken(Regexp):
    """Validate JSON Web Token."""

    EXAMPLE = (
        "eyJhbGciOiJFZERTQSJ9.eyJhIjogIjAifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    PATTERN = r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            JSONWebToken.PATTERN,
            error="Value {input} is not a valid JSON Web token",
        )


class SDJSONWebToken(Regexp):
    """Validate SD-JSON Web Token."""

    EXAMPLE = (
        "eyJhbGciOiJFZERTQSJ9."
        "eyJhIjogIjAifQ."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        "~WyJEM3BUSFdCYWNRcFdpREc2TWZKLUZnIiwgIkRFIl0"
        "~WyJPMTFySVRjRTdHcXExYW9oRkd0aDh3IiwgIlNBIl0"
        "~WyJkVmEzX1JlTGNsWTU0R1FHZm5oWlRnIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ"
    )
    PATTERN = r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+(?:~[a-zA-Z0-9._-]+)*~?$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            SDJSONWebToken.PATTERN,
            error="Value {input} is not a valid SD-JSON Web token",
        )


class DIDKey(Regexp):
    """Validate value against DID key specification."""

    EXAMPLE = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
    PATTERN = re.compile(rf"^did:key:z[{B58}]+$")

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            DIDKey.PATTERN, error="Value {input} is not in W3C did:key format"
        )


class DIDKeyOrRef(Regexp):
    """Validate value against DID key specification."""

    EXAMPLE = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
    PATTERN = re.compile(rf"^did:key:z[{B58}]+(?:#z[{B58}]+)?$")

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            DIDKeyOrRef.PATTERN, error="Value {input} is not a did:key or did:key ref"
        )


class DIDKeyRef(Regexp):
    """Validate value as DID key reference."""

    EXAMPLE = (
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
        "#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
    )
    PATTERN = re.compile(rf"^did:key:z[{B58}]+#z[{B58}]+$")

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            DIDKeyRef.PATTERN, error="Value {input} is not a did:key reference"
        )


class DIDWeb(Regexp):
    """Validate value against did:web specification."""

    EXAMPLE = "did:web:example.com"
    PATTERN = re.compile(r"^(did:web:)([a-zA-Z0-9%._-]*:)*[a-zA-Z0-9%._-]+$")

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            DIDWeb.PATTERN, error="Value {input} is not in W3C did:web format"
        )


class DIDWebvh(Regexp):
    """Validate value against did:webvh specification."""

    EXAMPLE = (
        "did:webvh:QmP9VWaTCHcyztDpRj9XSHvZbmYe3m9HZ61KoDtZgWaXVU:example.com%3A5000"
    )
    PATTERN = re.compile(r"^(did:webvh:)([a-zA-Z0-9%._-]*:)*[a-zA-Z0-9%._-]+$")

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            DIDWebvh.PATTERN, error="Value {input} is not in W3C did:webvh format"
        )


class DIDPosture(OneOf):
    """Validate value against defined DID postures."""

    EXAMPLE = DIDPostureEnum.WALLET_ONLY.moniker

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            choices=[did_posture.moniker for did_posture in DIDPostureEnum],
            error="Value {input} must be one of {choices}",
        )


class IndyDID(Regexp):
    """Validate value against indy DID."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv"
    PATTERN = re.compile(rf"^(did:sov:)?[{B58}]{{21,22}}$")

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            IndyDID.PATTERN,
            error="Value {input} is not an indy decentralized identifier (DID)",
        )


class AnoncredsDID(Regexp):
    """Validate value against anoncreds DID."""

    METHOD = r"([a-zA-Z0-9_]+)"
    NETWORK = r"(:[a-zA-Z0-9_.%-]+)?"  # Optional network
    METHOD_ID = r"([a-zA-Z0-9_.%-]+(:[a-zA-Z0-9_.%-]+)*)"

    EXAMPLE = "did:(method):WgWxqztrNooG92RXvxSTWv"
    PATTERN = re.compile(rf"^did:{METHOD}{NETWORK}:{METHOD_ID}")

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            DIDValidation.PATTERN,
            error="Value {input} is not an decentralized identifier (DID)",
        )


class DIDValidation(Regexp):
    """Validate value against any valid DID spec."""

    METHOD = r"([a-zA-Z0-9_]+)"
    NETWORK = r"(:[a-zA-Z0-9_.%-]+)?"  # Optional network
    METHOD_ID = r"([a-zA-Z0-9_.%-]+(:[a-zA-Z0-9_.%-]+)*)"
    PARAMS = r"((;[a-zA-Z0-9_.:%-]+=[a-zA-Z0-9_.:%-]*)*)"
    PATH = r"(\/[^#?]*)?"
    QUERY = r"([?][^#]*)?"
    FRAGMENT = r"(\#.*)?$"

    EXAMPLE = "did:peer:WgWxqztrNooG92RXvxSTWv"
    PATTERN = re.compile(
        rf"^did:{METHOD}{NETWORK}:{METHOD_ID}{PARAMS}{PATH}{QUERY}{FRAGMENT}$"
    )

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            DIDValidation.PATTERN,
            error="Value {input} is not a valid DID",
        )


# temporary support for short Indy DIDs in place of qualified DIDs
class MaybeIndyDID(Regexp):
    """Validate value against any valid DID spec or a short Indy DID."""

    EXAMPLE = DIDValidation.EXAMPLE
    PATTERN = re.compile(IndyDID.PATTERN.pattern + "|" + DIDValidation.PATTERN.pattern)

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            MaybeIndyDID.PATTERN,
            error="Value {input} is not a valid DID",
        )


class RawPublicEd25519VerificationKey2018(Regexp):
    """Validate value against (Ed25519VerificationKey2018) raw public key."""

    EXAMPLE = "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    PATTERN = rf"^[{B58}]{{43,44}}$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            RawPublicEd25519VerificationKey2018.PATTERN,
            error="Value {input} is not a raw Ed25519VerificationKey2018 key",
        )


class RoutingKey(Regexp):
    """Validate between indy or did key.

    Validate value against indy (Ed25519VerificationKey2018)
    raw public key or DID key specification.
    """

    EXAMPLE = DIDKey.EXAMPLE
    PATTERN = re.compile(
        DIDKey.PATTERN.pattern + "|" + RawPublicEd25519VerificationKey2018.PATTERN
    )

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            RoutingKey.PATTERN,
            error=(
                "Value {input} is not in W3C did:key"
                " or Ed25519VerificationKey2018 key format"
            ),
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
        """Initialize the instance."""

        super().__init__(
            IndyCredDefId.PATTERN,
            error="Value {input} is not an indy credential definition identifier",
        )


class AnoncredsCredDefId(Regexp):
    """Validate value against anoncreds credential definition identifier specification."""

    EXAMPLE = "did:(method):3:CL:20:tag"
    PATTERN = r"^(.+$)"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            AnoncredsCredDefId.PATTERN,
            error="Value {input} is not an anoncreds credential definition identifier",
        )


class MajorMinorVersion(Regexp):
    """Validate value against major minor version specification."""

    EXAMPLE = "1.0"
    PATTERN = r"^[0-9.]+$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            MajorMinorVersion.PATTERN,
            error="Value {input} is not a valid version major minor version (use only digits and '.')",  # noqa: E501
        )


class IndySchemaId(Regexp):
    """Validate value against indy schema identifier specification."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv:2:schema_name:1.0"
    PATTERN = rf"^[{B58}]{{21,22}}:2:.+:[0-9.]+$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            IndySchemaId.PATTERN,
            error="Value {input} is not an indy schema identifier",
        )


class AnoncredsSchemaId(Regexp):
    """Validate value against indy schema identifier specification."""

    EXAMPLE = "did:(method):2:schema_name:1.0"
    PATTERN = r"^(.+$)"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            AnoncredsSchemaId.PATTERN,
            error="Value {input} is not an anoncreds schema identifier",
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
        """Initialize the instance."""

        super().__init__(
            IndyRevRegId.PATTERN,
            error="Value {input} is not an indy revocation registry identifier",
        )


class AnoncredsRevRegId(Regexp):
    """Validate value against anoncreds revocation registry identifier specification."""

    EXAMPLE = "did:(method):4:did:<method>:3:CL:20:tag:CL_ACCUM:0"
    PATTERN = r"^(.+$)"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            AnoncredsRevRegId.PATTERN,
            error="Value {input} is not an anoncreds revocation registry identifier",
        )


class IndyCredRevId(Regexp):
    """Validate value against indy credential revocation identifier specification."""

    EXAMPLE = "12345"
    PATTERN = r"^[1-9][0-9]*$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            IndyCredRevId.PATTERN,
            error="Value {input} is not an indy credential revocation identifier",
        )


class AnonCredsCredRevId(Regexp):
    """Validate value against anoncreds credential revocation identifier specification."""

    EXAMPLE = "12345"
    PATTERN = r"^[1-9][0-9]*$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            AnonCredsCredRevId.PATTERN,
            error="Value {input} is not an anoncreds credential revocation identifier",
        )


class Predicate(OneOf):
    """Validate value against predicate."""

    EXAMPLE = ">="

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            choices=["<", "<=", ">=", ">"],
            error="Value {input} must be one of {choices}",
        )


class ISO8601DateTime(Regexp):
    """Validate value against ISO 8601 datetime format."""

    EXAMPLE = epoch_to_str(EXAMPLE_TIMESTAMP)
    PATTERN = (
        r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d"
        r"(?:\:(?:\d\d(?:\.\d{1,6})?))?(?:[+-]\d\d:?\d\d|Z|)$"
    )

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            ISO8601DateTime.PATTERN,
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
        """Initialize the instance."""

        super().__init__(
            RFC3339DateTime.PATTERN,
            error="Value {input} is not a date in valid format",
        )


class IndyWQL(Regexp):  # using Regexp brings in nice visual validator cue
    """Validate value as potential WQL query."""

    EXAMPLE = json.dumps({"attr::name::value": "Alex"})
    PATTERN = r"^{.*}$"

    def __init__(self):
        """Initialize the instance."""

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
        """Initialize the instance."""

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
        """Initialize the instance."""

        super().__init__(
            Base64.PATTERN,
            error="Value {input} is not a valid base64 encoding",
        )


class Base64URL(Regexp):
    """Validate base64 value."""

    EXAMPLE = "ey4uLn0="
    PATTERN = r"^[-_a-zA-Z0-9]*={0,2}$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            Base64URL.PATTERN,
            error="Value {input} is not a valid base64url encoding",
        )


class Base64URLNoPad(Regexp):
    """Validate base64 value."""

    EXAMPLE = "ey4uLn0"
    PATTERN = r"^[-_a-zA-Z0-9]*$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            Base64URLNoPad.PATTERN,
            error="Value {input} is not a valid unpadded base64url encoding",
        )


class SHA256Hash(Regexp):
    """Validate (binhex-encoded) SHA256 value."""

    EXAMPLE = "617a48c7c8afe0521efdc03e5bb0ad9e655893e6b4b51f0e794d70fba132aacb"
    PATTERN = r"^[a-fA-F0-9+/]{64}$"

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            SHA256Hash.PATTERN,
            error="Value {input} is not a valid (binhex-encoded) SHA-256 hash",
        )


class Base58SHA256Hash(Regexp):
    """Validate value against base58 encoding of SHA-256 hash."""

    EXAMPLE = "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    PATTERN = rf"^[{B58}]{{43,44}}$"

    def __init__(self):
        """Initialize the instance."""

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
        """Initialize the instance."""

        super().__init__(
            UUIDFour.PATTERN,
            error="Value {input} is not UUID4 (8-4-4-4-12 hex digits with digit#13=4)",
        )


class Uri(Regexp):
    """Validate value against URI on any scheme."""

    EXAMPLE = "https://www.w3.org/2018/credentials/v1"
    PATTERN = r"\w+:(\/?\/?)[^\s]+"

    def __init__(self):
        """Initialize the instance."""
        super().__init__(Uri.PATTERN, error="Value {input} is not URI")


class Endpoint(Regexp):  # using Regexp brings in nice visual validator cue
    """Validate value against endpoint URL on any scheme."""

    EXAMPLE = "https://myhost:8021"
    PATTERN = (
        r"^[A-Za-z0-9\.\-\+]+:"  # scheme
        r"//([A-Za-z0-9][.A-Za-z0-9-_]+[A-Za-z0-9])+"  # host
        r"(:[1-9][0-9]*)?"  # port
        r"(/[^?&#]+)?$"  # path
    )

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            Endpoint.PATTERN,
            error="Value {input} is not a valid endpoint",
        )


class EndpointType(OneOf):
    """Validate value against allowed endpoint/service types."""

    EXAMPLE = EndpointTypeEnum.ENDPOINT.w3c

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            choices=[e.w3c for e in EndpointTypeEnum],
            error="Value {input} must be one of {choices}",
        )


class CredentialType(Validator):
    """Credential Type."""

    CREDENTIAL_TYPE = "VerifiableCredential"
    EXAMPLE = [CREDENTIAL_TYPE, "AlumniCredential"]

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        length = len(value)
        if length < 1 or CredentialType.CREDENTIAL_TYPE not in value:
            raise ValidationError(f"type must include {CredentialType.CREDENTIAL_TYPE}")

        return value


class PresentationType(Validator):
    """Presentation Type."""

    PRESENTATION_TYPE = "VerifiablePresentation"
    EXAMPLE = [PRESENTATION_TYPE]

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        length = len(value)
        if length < 1 or PresentationType.PRESENTATION_TYPE not in value:
            raise ValidationError(
                f"type must include {PresentationType.PRESENTATION_TYPE}"
            )

        return value


class CredentialContext(Validator):
    """Credential Context."""

    FIRST_CONTEXT = "https://www.w3.org/2018/credentials/v1"
    VALID_CONTEXTS = [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/ns/credentials/v2",
    ]
    EXAMPLE = [VALID_CONTEXTS[0], "https://www.w3.org/2018/credentials/examples/v1"]

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""

        if not isinstance(value, list):
            raise ValidationError("Value must be a non-empty list.")

        if not value or value[0] not in CredentialContext.VALID_CONTEXTS:
            raise ValidationError(
                f"First context must be one of {CredentialContext.VALID_CONTEXTS}"
            )

        return value


class CredentialSubject(Validator):
    """Credential subject."""

    EXAMPLE = {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": {"id": "did:example:c276e12ec21ebfeb1f712ebc6f1"},
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        subjects = value if isinstance(value, list) else [value]

        for subject in subjects:
            if "id" in subject:
                uri_validator = Uri()
                try:
                    uri_validator(subject["id"])
                except ValidationError:
                    raise ValidationError(
                        f"credential subject id {subject['id']} must be URI"
                    ) from None

        return value


class CredentialStatus(Validator):
    """Credential status."""

    EXAMPLE = {
        "id": "https://example.com/credentials/status/3#94567",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "94567",
        "statusListCredential": "https://example.com/credentials/status/3",
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        # TODO write some tests

        return value


class IndyOrKeyDID(Regexp):
    """Indy or Key DID class."""

    PATTERN = "|".join(x.pattern for x in [DIDKey.PATTERN, IndyDID.PATTERN])
    EXAMPLE = IndyDID.EXAMPLE

    def __init__(
        self,
    ):
        """Initialize the instance."""
        super().__init__(
            IndyOrKeyDID.PATTERN,
            error="Value {input} is not in did:key or indy did format",
        )


# Instances for marshmallow schema specification
INT_EPOCH_VALIDATE = IntEpoch()
INT_EPOCH_EXAMPLE = IntEpoch.EXAMPLE

WHOLE_NUM_VALIDATE = WholeNumber()
WHOLE_NUM_EXAMPLE = WholeNumber.EXAMPLE

NUM_STR_WHOLE_VALIDATE = NumericStrWhole()
NUM_STR_WHOLE_EXAMPLE = NumericStrWhole.EXAMPLE

NUM_STR_ANY_VALIDATE = NumericStrAny()
NUM_STR_ANY_EXAMPLE = NumericStrAny.EXAMPLE

NATURAL_NUM_VALIDATE = NaturalNumber()
NATURAL_NUM_EXAMPLE = NaturalNumber.EXAMPLE

NUM_STR_NATURAL_VALIDATE = NumericStrNatural()
NUM_STR_NATURAL_EXAMPLE = NumericStrNatural.EXAMPLE

INDY_REV_REG_SIZE_VALIDATE = IndyRevRegSize()
INDY_REV_REG_SIZE_EXAMPLE = IndyRevRegSize.EXAMPLE

JWS_HEADER_KID_VALIDATE = JWSHeaderKid()
JWS_HEADER_KID_EXAMPLE = JWSHeaderKid.EXAMPLE

NON_SD_LIST_VALIDATE = NonSDList()
NON_SD_LIST_EXAMPLE = NonSDList().EXAMPLE

JWT_VALIDATE = JSONWebToken()
JWT_EXAMPLE = JSONWebToken.EXAMPLE

SD_JWT_VALIDATE = SDJSONWebToken()
SD_JWT_EXAMPLE = SDJSONWebToken.EXAMPLE

DID_KEY_VALIDATE = DIDKey()
DID_KEY_EXAMPLE = DIDKey.EXAMPLE

DID_KEY_OR_REF_VALIDATE = DIDKeyOrRef()
DID_KEY_OR_REF_EXAMPLE = DIDKeyOrRef.EXAMPLE

DID_KEY_REF_VALIDATE = DIDKeyRef()
DID_KEY_REF_EXAMPLE = DIDKeyRef.EXAMPLE

DID_POSTURE_VALIDATE = DIDPosture()
DID_POSTURE_EXAMPLE = DIDPosture.EXAMPLE

DID_WEB_VALIDATE = DIDWeb()
DID_WEB_EXAMPLE = DIDWeb.EXAMPLE

DID_WEBVH_VALIDATE = DIDWebvh()
DID_WEBVH_EXAMPLE = DIDWebvh.EXAMPLE

ROUTING_KEY_VALIDATE = RoutingKey()
ROUTING_KEY_EXAMPLE = RoutingKey.EXAMPLE

INDY_DID_VALIDATE = IndyDID()
INDY_DID_EXAMPLE = IndyDID.EXAMPLE

GENERIC_DID_VALIDATE = MaybeIndyDID()
GENERIC_DID_EXAMPLE = MaybeIndyDID.EXAMPLE

RAW_ED25519_2018_PUBLIC_KEY_VALIDATE = RawPublicEd25519VerificationKey2018()
RAW_ED25519_2018_PUBLIC_KEY_EXAMPLE = RawPublicEd25519VerificationKey2018.EXAMPLE

INDY_SCHEMA_ID_VALIDATE = IndySchemaId()
INDY_SCHEMA_ID_EXAMPLE = IndySchemaId.EXAMPLE

ANONCREDS_SCHEMA_ID_VALIDATE = AnoncredsSchemaId()
ANONCREDS_SCHEMA_ID_EXAMPLE = AnoncredsSchemaId.EXAMPLE

INDY_CRED_DEF_ID_VALIDATE = IndyCredDefId()
INDY_CRED_DEF_ID_EXAMPLE = IndyCredDefId.EXAMPLE

ANONCREDS_CRED_DEF_ID_VALIDATE = AnoncredsCredDefId()
ANONCREDS_CRED_DEF_ID_EXAMPLE = AnoncredsCredDefId.EXAMPLE

INDY_REV_REG_ID_VALIDATE = IndyRevRegId()
INDY_REV_REG_ID_EXAMPLE = IndyRevRegId.EXAMPLE

ANONCREDS_REV_REG_ID_VALIDATE = AnoncredsRevRegId()
ANONCREDS_REV_REG_ID_EXAMPLE = AnoncredsRevRegId.EXAMPLE

INDY_CRED_REV_ID_VALIDATE = IndyCredRevId()
INDY_CRED_REV_ID_EXAMPLE = IndyCredRevId.EXAMPLE

ANONCREDS_CRED_REV_ID_VALIDATE = AnonCredsCredRevId()
ANONCREDS_CRED_REV_ID_EXAMPLE = AnonCredsCredRevId.EXAMPLE

MAJOR_MINOR_VERSION_VALIDATE = MajorMinorVersion()
MAJOR_MINOR_VERSION_EXAMPLE = MajorMinorVersion.EXAMPLE

PREDICATE_VALIDATE = Predicate()
PREDICATE_EXAMPLE = Predicate.EXAMPLE

ISO8601_DATETIME_VALIDATE = ISO8601DateTime()
ISO8601_DATETIME_EXAMPLE = ISO8601DateTime.EXAMPLE

RFC3339_DATETIME_VALIDATE = RFC3339DateTime()
RFC3339_DATETIME_EXAMPLE = RFC3339DateTime.EXAMPLE

INDY_WQL_VALIDATE = IndyWQL()
INDY_WQL_EXAMPLE = IndyWQL.EXAMPLE

INDY_EXTRA_WQL_VALIDATE = IndyExtraWQL()
INDY_EXTRA_WQL_EXAMPLE = IndyExtraWQL.EXAMPLE

BASE64_VALIDATE = Base64()
BASE64_EXAMPLE = Base64.EXAMPLE

BASE64URL_VALIDATE = Base64URL()
BASE64URL_EXAMPLE = Base64URL.EXAMPLE

BASE64URL_NO_PAD_VALIDATE = Base64URLNoPad()
BASE64URL_NO_PAD_EXAMPLE = Base64URLNoPad.EXAMPLE

SHA256_VALIDATE = SHA256Hash()
SHA256_EXAMPLE = SHA256Hash.EXAMPLE

BASE58_SHA256_HASH_VALIDATE = Base58SHA256Hash()
BASE58_SHA256_HASH_EXAMPLE = Base58SHA256Hash.EXAMPLE

UUID4_VALIDATE = UUIDFour()
UUID4_EXAMPLE = UUIDFour.EXAMPLE

ENDPOINT_VALIDATE = Endpoint()
ENDPOINT_EXAMPLE = Endpoint.EXAMPLE

ENDPOINT_TYPE_VALIDATE = EndpointType()
ENDPOINT_TYPE_EXAMPLE = EndpointType.EXAMPLE

CREDENTIAL_TYPE_VALIDATE = CredentialType()
CREDENTIAL_TYPE_EXAMPLE = CredentialType.EXAMPLE

CREDENTIAL_CONTEXT_VALIDATE = CredentialContext()
CREDENTIAL_CONTEXT_EXAMPLE = CredentialContext.EXAMPLE

URI_VALIDATE = Uri()
URI_EXAMPLE = Uri.EXAMPLE

CREDENTIAL_SUBJECT_VALIDATE = CredentialSubject()
CREDENTIAL_SUBJECT_EXAMPLE = CredentialSubject.EXAMPLE

CREDENTIAL_STATUS_VALIDATE = CredentialStatus()
CREDENTIAL_STATUS_EXAMPLE = CredentialStatus.EXAMPLE

PRESENTATION_TYPE_VALIDATE = PresentationType()
PRESENTATION_TYPE_EXAMPLE = PresentationType.EXAMPLE

INDY_OR_KEY_DID_VALIDATE = IndyOrKeyDID()
INDY_OR_KEY_DID_EXAMPLE = IndyOrKeyDID.EXAMPLE

ANONCREDS_DID_VALIDATE = AnoncredsDID()
ANONCREDS_DID_EXAMPLE = AnoncredsDID.EXAMPLE
