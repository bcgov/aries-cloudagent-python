from asynctest import TestCase as AsyncTestCase

from ......messaging.decorators.attach_decorator import AttachDecorator

from ...message_types import ATTACHMENT_FORMAT, CRED_20_PROPOSAL
from ...messages.cred_format import V20CredFormat
from ...messages.inner.cred_preview import V20CredAttrSpec, V20CredPreview
from ...messages.cred_proposal import V20CredProposal

from ..cred_ex_record import V20CredExRecord

TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
SCHEMA_NAME = "bc-reg"
SCHEMA_TXN = 12
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:1.0"
SCHEMA = {
    "ver": "1.0",
    "id": SCHEMA_ID,
    "name": SCHEMA_NAME,
    "version": "1.0",
    "attrNames": ["legalName", "jurisdictionId", "incorporationDate"],
    "seqNo": SCHEMA_TXN,
}
CRED_DEF_ID = f"{TEST_DID}:3:CL:12:tag1"
CRED_PREVIEW = V20CredPreview(
    attributes=(
        V20CredAttrSpec.list_plain({"test": "123", "hello": "world"})
        + [V20CredAttrSpec(name="icon", value="cG90YXRv", mime_type="image/png")]
    )
)
INDY_FILTER = {
    "schema_id": SCHEMA_ID,
    "cred_def_id": CRED_DEF_ID,
}


class TestV20CredExRecord(AsyncTestCase):
    async def test_record(self):
        same = [
            V20CredExRecord(
                cred_ex_id="dummy-0",
                thread_id="thread-0",
                initiator=V20CredExRecord.INITIATOR_SELF,
                role=V20CredExRecord.ROLE_ISSUER,
            )
        ] * 2
        diff = [
            V20CredExRecord(
                cred_ex_id="dummy-1",
                initiator=V20CredExRecord.INITIATOR_SELF,
                role=V20CredExRecord.ROLE_ISSUER,
            ),
            V20CredExRecord(
                cred_ex_id="dummy-0",
                thread_id="thread-1",
                initiator=V20CredExRecord.INITIATOR_SELF,
                role=V20CredExRecord.ROLE_ISSUER,
            ),
            V20CredExRecord(
                cred_ex_id="dummy-0",
                thread_id="thread-1",
                initiator=V20CredExRecord.INITIATOR_EXTERNAL,
                role=V20CredExRecord.ROLE_ISSUER,
            ),
        ]

        for i in range(len(same) - 1):
            for j in range(i, len(same)):
                assert same[i] == same[j]

        for i in range(len(diff) - 1):
            for j in range(i, len(diff)):
                assert diff[i] == diff[j] if i == j else diff[i] != diff[j]

        assert not same[0].cred_preview  # cover non-proposal's non-preview

    def test_serde(self):
        """Test de/serialization."""

        cred_proposal = V20CredProposal(
            comment="Hello World",
            credential_preview=CRED_PREVIEW,
            formats=[
                V20CredFormat(
                    attach_id="indy",
                    format_=ATTACHMENT_FORMAT[CRED_20_PROPOSAL][
                        V20CredFormat.Format.INDY.api
                    ],
                )
            ],
            filters_attach=[AttachDecorator.data_base64(INDY_FILTER, ident="indy")],
        )
        for proposal_arg in [cred_proposal, cred_proposal.serialize()]:
            cx_rec = V20CredExRecord(
                cred_ex_id="dummy",
                connection_id="0000...",
                thread_id="dummy-thid",
                parent_thread_id="dummy-pthid",
                initiator=V20CredExRecord.INITIATOR_EXTERNAL,
                role=V20CredExRecord.ROLE_ISSUER,
                state=V20CredExRecord.STATE_PROPOSAL_RECEIVED,
                cred_proposal=proposal_arg,
                cred_offer=None,
                cred_request=None,
                cred_issue=None,
                auto_offer=False,
                auto_issue=False,
                auto_remove=True,
                error_msg=None,
                trace=False,
            )
            assert type(cx_rec.cred_proposal) == dict
            ser = cx_rec.serialize()
            deser = V20CredExRecord.deserialize(ser)
            assert type(deser.cred_proposal) == dict
