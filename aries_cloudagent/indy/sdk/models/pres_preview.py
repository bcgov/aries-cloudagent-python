"""A presentation preview inner object."""

from enum import Enum
from time import time
from typing import Mapping, Sequence

from marshmallow import EXCLUDE, fields

from ....ledger.indy import IndySdkLedger
from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.util import canon
from ....messaging.valid import INDY_CRED_DEF_ID, INDY_PREDICATE
from ....protocols.didcomm_prefix import DIDCommPrefix
from ....wallet.util import b64_to_str

from ...util import generate_pr_nonce

from .non_rev_interval import IndyNonRevocationInterval
from .predicate import Predicate

PRESENTATION_PREVIEW = "present-proof/1.0/presentation-preview"  # message type


class IndyPresPredSpec(BaseModel):
    """Class representing a predicate specification within a presentation preview."""

    class Meta:
        """Pred spec metadata."""

        schema_class = "IndyPresPredSpecSchema"

    def __init__(
        self,
        name: str,
        *,
        cred_def_id: str = None,
        predicate: str,
        threshold: int,
        **kwargs,
    ):
        """
        Initialize  preview object.

        Args:
            name: attribute name
            cred_def_id: credential definition identifier
            predicate: predicate type (e.g., ">=")
            threshold: threshold value

        """
        super().__init__(**kwargs)
        self.name = name
        self.cred_def_id = cred_def_id
        self.predicate = predicate
        self.threshold = threshold

    def __eq__(self, other):
        """Equality comparator."""

        if canon(self.name) != canon(other.name):
            return False  # distinct attribute names modulo canonicalization

        if self.cred_def_id != other.cred_def_id:
            return False

        if self.predicate != other.predicate:
            return False

        return self.threshold == other.threshold


class IndyPresPredSpecSchema(BaseModelSchema):
    """Predicate specifiation schema."""

    class Meta:
        """Predicate specifiation schema metadata."""

        model_class = IndyPresPredSpec
        unknown = EXCLUDE

    name = fields.Str(description="Attribute name", required=True, example="high_score")
    cred_def_id = fields.Str(
        description="Credential definition identifier",
        required=False,
        **INDY_CRED_DEF_ID,
    )
    predicate = fields.Str(
        description="Predicate type ('<', '<=', '>=', or '>')",
        required=True,
        **INDY_PREDICATE,
    )
    threshold = fields.Int(description="Threshold value", required=True, strict=True)


class IndyPresAttrSpec(BaseModel):
    """Class representing an attibute specification within a presentation preview."""

    class Meta:
        """Attr spec metadata."""

        schema_class = "IndyPresAttrSpecSchema"

    class Posture(Enum):
        """Attribute posture: self-attested, revealed claim or unrevealed claim."""

        SELF_ATTESTED = 0
        REVEALED_CLAIM = 1
        UNREVEALED_CLAIM = 2

    def __init__(
        self,
        name: str,
        cred_def_id: str = None,
        mime_type: str = None,
        value: str = None,
        referent: str = None,
        **kwargs,
    ):
        """
        Initialize attribute specification object.

        Args:
            name: attribute name
            cred_def_id: credential definition identifier
                (None for self-attested attribute)
            mime_type: MIME type
            value: attribute value as credential stores it
                (None for unrevealed attribute)
            referent: credential referent

        """
        super().__init__(**kwargs)
        self.name = name
        self.cred_def_id = cred_def_id
        self.mime_type = mime_type.lower() if mime_type else None
        self.value = value
        self.referent = referent

    @staticmethod
    def list_plain(plain: dict, cred_def_id: str, referent: str = None):
        """
        Return a list of `IndyPresAttrSpec` on input cred def id.

        Args:
            plain: dict mapping names to values
            cred_def_id: credential definition identifier to specify
            referent: single referent to use, omit for none

        Returns:
            List of IndyPresAttrSpec on input cred def id with no MIME types

        """
        return [
            IndyPresAttrSpec(
                name=k, cred_def_id=cred_def_id, value=plain[k], referent=referent
            )
            for k in plain
        ]

    @property
    def posture(self) -> "IndyPresAttrSpec.Posture":
        """Attribute posture: self-attested, revealed claim, or unrevealed claim."""

        if self.cred_def_id:
            if self.value:
                return IndyPresAttrSpec.Posture.REVEALED_CLAIM
            return IndyPresAttrSpec.Posture.UNREVEALED_CLAIM
        if self.value:
            return IndyPresAttrSpec.Posture.SELF_ATTESTED

        return None

    def b64_decoded_value(self) -> str:
        """Value, base64-decoded if applicable."""

        return b64_to_str(self.value) if self.value and self.mime_type else self.value

    def satisfies(self, pred_spec: IndyPresPredSpec):
        """Whether current specified attribute satisfies input specified predicate."""

        return bool(
            self.value
            and not self.mime_type
            and canon(self.name) == canon(pred_spec.name)
            and not pred_spec.cred_def_id
            or (self.cred_def_id == pred_spec.cred_def_id)
            and Predicate.get(pred_spec.predicate).value.yes(
                self.value, pred_spec.threshold
            )
        )

    def __eq__(self, other):
        """Equality comparator."""

        if canon(self.name) != canon(other.name):
            return False  # distinct attribute names

        if self.cred_def_id != other.cred_def_id:
            return False  # distinct attribute cred def ids

        if self.mime_type != other.mime_type:
            return False  # distinct MIME types

        if self.referent != other.referent:
            return False  # distinct credential referents

        return self.b64_decoded_value() == other.b64_decoded_value()


class IndyPresAttrSpecSchema(BaseModelSchema):
    """Attribute specifiation schema."""

    class Meta:
        """Attribute specifiation schema metadata."""

        model_class = IndyPresAttrSpec
        unknown = EXCLUDE

    name = fields.Str(
        description="Attribute name", required=True, example="favourite_drink"
    )
    cred_def_id = fields.Str(required=False, **INDY_CRED_DEF_ID)
    mime_type = fields.Str(
        description="MIME type (default null)",
        required=False,
        data_key="mime-type",
        example="image/jpeg",
    )
    value = fields.Str(description="Attribute value", required=False, example="martini")
    referent = fields.Str(
        description="Credential referent", required=False, example="0"
    )


class IndyPresPreview(BaseModel):
    """Class representing presentation preview."""

    class Meta:
        """Presentation preview metadata."""

        schema_class = "IndyPresPreviewSchema"
        message_type = PRESENTATION_PREVIEW

    def __init__(
        self,
        *,
        _type: str = None,
        attributes: Sequence[IndyPresAttrSpec] = None,
        predicates: Sequence[IndyPresPredSpec] = None,
        **kwargs,
    ):
        """
        Initialize presentation preview object.

        Args:
            _type: formalism for Marshmallow model creation: ignored
            attributes: list of attribute specifications
            predicates: list of predicate specifications

        """
        super().__init__(**kwargs)
        self.attributes = list(attributes) if attributes else []
        self.predicates = list(predicates) if predicates else []

    @property
    def _type(self):
        """Accessor for message type."""

        return DIDCommPrefix.qualify_current(IndyPresPreview.Meta.message_type)

    def has_attr_spec(self, cred_def_id: str, name: str, value: str) -> bool:
        """
        Return whether preview contains given attribute specification.

        Args:
            cred_def_id: credential definition identifier
            name: attribute name
            value: attribute value

        Returns:
            Whether preview contains matching attribute specification.

        """

        return any(
            canon(a.name) == canon(name)
            and a.value in (value, None)
            and a.cred_def_id == cred_def_id
            for a in self.attributes
        )

    async def indy_proof_request(
        self,
        name: str = None,
        version: str = None,
        nonce: str = None,
        ledger: IndySdkLedger = None,
        non_revoc_intervals: Mapping[str, IndyNonRevocationInterval] = None,
    ) -> dict:
        """
        Return indy proof request corresponding to presentation preview.

        Typically the verifier turns the proof preview into a proof request.

        Args:
            name: for proof request
            version: version for proof request
            nonce: nonce for proof request
            ledger: ledger with credential definitions, to check for revocation support
            non_revoc_intervals: non-revocation interval to use per cred def id
                where applicable (default from and to the current time if applicable)

        Returns:
            Indy proof request dict.

        """

        def non_revoc(cred_def_id: str) -> IndyNonRevocationInterval:
            """Non-revocation interval to use for input cred def id."""

            nonlocal epoch_now
            nonlocal non_revoc_intervals

            return (non_revoc_intervals or {}).get(
                cred_def_id, IndyNonRevocationInterval(epoch_now, epoch_now)
            )

        epoch_now = int(time())

        proof_req = {
            "name": name or "proof-request",
            "version": version or "1.0",
            "nonce": nonce or await generate_pr_nonce(),
            "requested_attributes": {},
            "requested_predicates": {},
        }

        attr_specs_names = {}
        for attr_spec in self.attributes:
            if attr_spec.posture == IndyPresAttrSpec.Posture.SELF_ATTESTED:
                proof_req["requested_attributes"][
                    "self_{}_uuid".format(canon(attr_spec.name))
                ] = {"name": attr_spec.name}
                continue

            cd_id = attr_spec.cred_def_id
            revoc_support = False
            if cd_id:
                if ledger:
                    async with ledger:
                        revoc_support = (await ledger.get_credential_definition(cd_id))[
                            "value"
                        ].get("revocation")
                interval = non_revoc(cd_id) if revoc_support else None

            if attr_spec.referent:
                if attr_spec.referent in attr_specs_names:
                    attr_specs_names[attr_spec.referent]["names"].append(attr_spec.name)
                else:
                    attr_specs_names[attr_spec.referent] = {
                        "names": [attr_spec.name],
                        **{
                            "restrictions": [{"cred_def_id": cd_id}]
                            for _ in [""]
                            if cd_id
                        },
                        **{
                            "non_revoked": interval.serialize()
                            for _ in [""]
                            if revoc_support
                        },
                    }
            else:
                proof_req["requested_attributes"][
                    "{}_{}_uuid".format(
                        len(proof_req["requested_attributes"]),
                        canon(attr_spec.name),
                    )
                ] = {
                    "name": attr_spec.name,
                    **{"restrictions": [{"cred_def_id": cd_id}] for _ in [""] if cd_id},
                    **{
                        "non_revoked": interval.serialize()
                        for _ in [""]
                        if revoc_support
                    },
                }

        for (reft, attr_spec) in attr_specs_names.items():
            proof_req["requested_attributes"][
                "{}_{}_uuid".format(
                    len(proof_req["requested_attributes"]), canon(attr_spec["names"][0])
                )
            ] = attr_spec

        for pred_spec in self.predicates:
            cd_id = pred_spec.cred_def_id
            revoc_support = False
            if cd_id:
                if ledger:
                    async with ledger:
                        revoc_support = (await ledger.get_credential_definition(cd_id))[
                            "value"
                        ].get("revocation")
                interval = non_revoc(cd_id) if revoc_support else None

            proof_req["requested_predicates"][
                "{}_{}_{}_uuid".format(
                    len(proof_req["requested_predicates"]),
                    canon(pred_spec.name),
                    Predicate.get(pred_spec.predicate).value.fortran,
                )
            ] = {
                "name": pred_spec.name,
                "p_type": pred_spec.predicate,
                "p_value": pred_spec.threshold,
                **{"restrictions": [{"cred_def_id": cd_id}] for _ in [""] if cd_id},
                **{"non_revoked": interval.serialize() for _ in [""] if revoc_support},
            }

        return proof_req

    def __eq__(self, other):
        """Equality comparator."""

        for part in vars(self):
            if getattr(self, part, None) != getattr(other, part, None):
                return False
        return True


class IndyPresPreviewSchema(BaseModelSchema):
    """Presentation preview schema."""

    class Meta:
        """Presentation preview schema metadata."""

        model_class = IndyPresPreview
        unknown = EXCLUDE

    _type = fields.Str(
        description="Message type identifier",
        required=False,
        example=DIDCommPrefix.qualify_current(PRESENTATION_PREVIEW),
        data_key="@type",
    )
    attributes = fields.Nested(IndyPresAttrSpecSchema, required=True, many=True)
    predicates = fields.Nested(IndyPresPredSpecSchema, required=True, many=True)
