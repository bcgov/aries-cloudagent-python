import json
from datetime import datetime, timezone
from unittest import TestCase

from ......indy.sdk.models.pres_preview import PRESENTATION_PREVIEW
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......messaging.util import str_to_datetime, str_to_epoch

from .....didcomm_prefix import DIDCommPrefix

from ...message_types import ATTACH_DECO_IDS, PRESENTATION_REQUEST

from ..presentation_request import PresentationRequest, PresentationRequestSchema


NOW_8601 = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(" ", "seconds")
NOW_EPOCH = str_to_epoch(NOW_8601)
CD_ID = "GMm4vMw8LLrLJjp81kRRLp:3:CL:12:tag"
INDY_PROOF_REQ = json.loads(
    f"""{{
    "name": "proof-req",
    "version": "1.0",
    "nonce": "12345",
    "requested_attributes": {{
        "0_player_uuid": {{
            "name": "player",
            "restrictions": [
                {{
                    "cred_def_id": "{CD_ID}"
                }}
            ],
            "non_revoked": {{
                "from": {NOW_EPOCH},
                "to": {NOW_EPOCH}
            }}
        }},
        "0_screencapture_uuid": {{
            "name": "screenCapture",
            "restrictions": [
                {{
                    "cred_def_id": "{CD_ID}"
                }}
            ],
            "non_revoked": {{
                "from": {NOW_EPOCH},
                "to": {NOW_EPOCH}
            }}
        }}
    }},
    "requested_predicates": {{
        "0_highscore_GE_uuid": {{
            "name": "highScore",
            "p_type": ">=",
            "p_value": 1000000,
            "restrictions": [
                {{
                    "cred_def_id": "{CD_ID}"
                }}
            ],
            "non_revoked": {{
                "from": {NOW_EPOCH},
                "to": {NOW_EPOCH}
            }}
        }}
    }}
}}"""
)

PRES_REQ = PresentationRequest(
    comment="Test",
    request_presentations_attach=[
        AttachDecorator.data_base64(
            mapping=INDY_PROOF_REQ,
            ident=ATTACH_DECO_IDS[PRESENTATION_REQUEST],
        )
    ],
)


class TestPresentationRequest(TestCase):
    """Presentation request tests."""

    def test_init(self):
        """Test initializer."""
        assert PRES_REQ.request_presentations_attach[0].content == INDY_PROOF_REQ
        assert PRES_REQ.indy_proof_request(0) == INDY_PROOF_REQ

    def test_type(self):
        """Test type."""
        assert PRES_REQ._type == DIDCommPrefix.qualify_current(PRESENTATION_REQUEST)

    def test_deserialize(self):
        """Test deserialization."""
        dump = json.dumps(
            {
                "@type": DIDCommPrefix.qualify_current(PRESENTATION_REQUEST),
                "comment": "Hello World",
                "request_presentations~attach": [
                    AttachDecorator.data_base64(
                        mapping=INDY_PROOF_REQ,
                        ident=ATTACH_DECO_IDS[PRESENTATION_REQUEST],
                    ).serialize()
                ],
            }
        )

        presentation_request = PresentationRequest.deserialize(dump)
        assert type(presentation_request) == PresentationRequest

    def test_serialize(self):
        """Test serialization."""
        pres_req_dict = PRES_REQ.serialize()
        pres_req_dict.pop("@id")

        assert pres_req_dict == {
            "@type": DIDCommPrefix.qualify_current(PRESENTATION_REQUEST),
            "request_presentations~attach": [
                AttachDecorator.data_base64(
                    mapping=INDY_PROOF_REQ,
                    ident=ATTACH_DECO_IDS[PRESENTATION_REQUEST],
                ).serialize()
            ],
            "comment": "Test",
        }


class TestPresentationRequestSchema(TestCase):
    """Test presentation request schema"""

    def test_make_model(self):
        """Test making model."""
        pres_req_dict = PRES_REQ.serialize()
        """
        Looks like: {
            "@type": ".../present-proof/1.0/request-presentation",
            "@id": "f49773e3-bd56-4868-a5f1-456d1e6d1a16",
            "comment": "Test",
            "request_presentations~attach": [
                {
                    "mime-type": "application/json",
                    "data": {
                        "base64": "eyJuYW..."
                    }
                }
            ]
        }
        """

        model_instance = PRES_REQ.deserialize(pres_req_dict)
        assert isinstance(model_instance, PresentationRequest)
