from unittest import TestCase

from ......indy.sdk.models.pres_preview import (
    IndyPresAttrSpec,
    IndyPresPredSpec,
    IndyPresPreview,
    PRESENTATION_PREVIEW,
)

from .....didcomm_prefix import DIDCommPrefix

from ...message_types import PRESENTATION_PROPOSAL

from ..presentation_proposal import PresentationProposal


S_ID = "NcYxiDXkpYi6ov5FcYDi1e:2:vidya:1.0"
CD_ID = f"NcYxiDXkpYi6ov5FcYDi1e:3:CL:{S_ID}:tag1"
PRES_PREVIEW = IndyPresPreview(
    attributes=[
        IndyPresAttrSpec(name="player", cred_def_id=CD_ID, value="Richie Knucklez"),
        IndyPresAttrSpec(
            name="screenCapture",
            cred_def_id=CD_ID,
            mime_type="image/png",
            value="aW1hZ2luZSBhIHNjcmVlbiBjYXB0dXJl",
        ),
    ],
    predicates=[
        IndyPresPredSpec(
            name="highScore", cred_def_id=CD_ID, predicate=">=", threshold=1000000
        )
    ],
)


class TestPresentationProposal(TestCase):
    """Presentation proposal tests."""

    def test_init(self):
        """Test initializer."""
        presentation_proposal = PresentationProposal(
            comment="Hello World", presentation_proposal=PRES_PREVIEW
        )
        assert presentation_proposal.presentation_proposal == PRES_PREVIEW

    def test_type(self):
        """Test type."""
        presentation_proposal = PresentationProposal(
            comment="Hello World", presentation_proposal=PRES_PREVIEW
        )
        assert presentation_proposal._type == DIDCommPrefix.qualify_current(
            PRESENTATION_PROPOSAL
        )

    def test_deserialize(self):
        """Test deserialization."""
        obj = {
            "@type": DIDCommPrefix.qualify_current(PRESENTATION_PROPOSAL),
            "comment": "Hello World",
            "presentation_proposal": PRES_PREVIEW.serialize(),
        }

        pres_proposal = PresentationProposal.deserialize(obj)
        assert type(pres_proposal) == PresentationProposal

    def test_serialize(self):
        """Test serialization."""

        pres_proposal = PresentationProposal(
            comment="Hello World", presentation_proposal=PRES_PREVIEW
        )

        pres_proposal_dict = pres_proposal.serialize()
        pres_proposal_dict.pop("@id")

        assert pres_proposal_dict == {
            "@type": DIDCommPrefix.qualify_current(PRESENTATION_PROPOSAL),
            "comment": "Hello World",
            "presentation_proposal": PRES_PREVIEW.serialize(),
        }


class TestPresentationProposalSchema(TestCase):
    """Test presentation cred proposal schema."""

    presentation_proposal = PresentationProposal(
        comment="Hello World", presentation_proposal=PRES_PREVIEW
    )

    def test_make_model(self):
        """Test making model."""
        data = self.presentation_proposal.serialize()
        model_instance = PresentationProposal.deserialize(data)
        assert isinstance(model_instance, PresentationProposal)
