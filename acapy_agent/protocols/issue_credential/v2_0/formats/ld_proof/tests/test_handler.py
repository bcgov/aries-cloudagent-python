from copy import deepcopy
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from marshmallow import ValidationError

from .......messaging.decorators.attach_decorator import AttachDecorator
from .......resolver.did_resolver import DIDResolver
from .......storage.vc_holder.base import VCHolder
from .......storage.vc_holder.vc_record import VCRecord
from .......tests import mock
from .......utils.testing import create_test_profile
from .......vc.ld_proofs import DocumentLoader, DocumentVerificationResult
from .......vc.ld_proofs.constants import (
    SECURITY_CONTEXT_BBS_URL,
    SECURITY_CONTEXT_ED25519_2020_URL,
)
from .......vc.ld_proofs.error import LinkedDataProofException
from .......vc.vc_ld.manager import VcLdpManager
from .......vc.vc_ld.models.credential import VerifiableCredential
from .......vc.vc_ld.models.options import LDProofVCOptions
from .......wallet.base import BaseWallet
from .......wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
    DefaultVerificationKeyStrategy,
)
from ....message_types import (
    ATTACHMENT_FORMAT,
    CRED_20_ISSUE,
    CRED_20_OFFER,
    CRED_20_PROPOSAL,
    CRED_20_REQUEST,
)
from ....messages.cred_format import V20CredFormat
from ....messages.cred_issue import V20CredIssue
from ....messages.cred_offer import V20CredOffer
from ....messages.cred_proposal import V20CredProposal
from ....messages.cred_request import V20CredRequest
from ....models.cred_ex_record import V20CredExRecord
from ....models.detail.ld_proof import V20CredExRecordLDProof
from ...handler import V20CredFormatError
from .. import handler as test_module
from ..handler import LOGGER as LD_PROOF_LOGGER
from ..handler import LDProofCredFormatHandler
from ..models.cred_detail import LDProofVCDetail
from .fixtures import (
    LD_PROOF_VC_DETAIL,
    LD_PROOF_VC_DETAIL_BBS,
    LD_PROOF_VC_DETAIL_ED25519_2020,
    LD_PROOF_VC,
)


class TestV20LDProofCredFormatHandler(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.holder = mock.MagicMock()
        self.wallet = mock.MagicMock(BaseWallet, autospec=True)

        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(
            BaseWallet, mock.MagicMock(BaseWallet, autospec=True)
        )
        self.profile.context.injector.bind_instance(
            VCHolder, mock.MagicMock(VCHolder, autospec=True)
        )
        # Set custom document loader
        # mock_document_loader = mock.MagicMock(DocumentLoader, autospec=True)
        # mock_document_loader.custom_document_loader = custom_document_loader
        self.profile.context.injector.bind_instance(DIDResolver, DIDResolver([]))
        self.profile.context.injector.bind_instance(
            DocumentLoader, DocumentLoader(self.profile)
        )

        # Set default verkey ID strategy
        self.profile.context.injector.bind_instance(
            BaseVerificationKeyStrategy, DefaultVerificationKeyStrategy()
        )

        self.manager = VcLdpManager(self.profile)
        self.profile.context.injector.bind_instance(VcLdpManager, self.manager)
        self.handler = LDProofCredFormatHandler(self.profile)

        self.cred_proposal = V20CredProposal(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_PROPOSAL][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            filters_attach=[AttachDecorator.data_base64(LD_PROOF_VC_DETAIL, ident="0")],
        )

        assert self.handler.profile

    async def test_validate_fields(self):
        # Test correct data
        self.handler.validate_fields(CRED_20_PROPOSAL, LD_PROOF_VC_DETAIL)
        self.handler.validate_fields(CRED_20_OFFER, LD_PROOF_VC_DETAIL)
        self.handler.validate_fields(CRED_20_REQUEST, LD_PROOF_VC_DETAIL)
        self.handler.validate_fields(CRED_20_ISSUE, LD_PROOF_VC)

        incorrect_detail = {
            **LD_PROOF_VC_DETAIL,
            "credential": {**LD_PROOF_VC_DETAIL["credential"], "credentialSubject": None},
        }

        # test incorrect proposal
        with self.assertRaises(ValidationError):
            self.handler.validate_fields(CRED_20_PROPOSAL, incorrect_detail)

        # test incorrect offer
        with self.assertRaises(ValidationError):
            self.handler.validate_fields(CRED_20_OFFER, incorrect_detail)

        # test incorrect request
        with self.assertRaises(ValidationError):
            self.handler.validate_fields(CRED_20_REQUEST, incorrect_detail)

        # test incorrect cred
        with self.assertRaises(ValidationError):
            incorrect_cred = LD_PROOF_VC.copy()
            incorrect_cred.pop("credentialSubject")
            self.handler.validate_fields(CRED_20_ISSUE, incorrect_cred)

    async def test_get_ld_proof_detail_record(self):
        cred_ex_id = "dummy"
        details_ld_proof = [
            V20CredExRecordLDProof(
                cred_ex_id=cred_ex_id,
            ),
            V20CredExRecordLDProof(
                cred_ex_id=cred_ex_id,
            ),
        ]
        async with self.profile.session() as session:
            await details_ld_proof[0].save(session)
            await details_ld_proof[1].save(session)  # exercise logger warning on get()

        with mock.patch.object(
            LD_PROOF_LOGGER, "warning", mock.MagicMock()
        ) as mock_warning:
            assert await self.handler.get_detail_record(cred_ex_id) in details_ld_proof
            mock_warning.assert_called_once()

    async def test_create_proposal(self):
        cred_ex_record = mock.MagicMock()

        (cred_format, attachment) = await self.handler.create_proposal(
            cred_ex_record, deepcopy(LD_PROOF_VC_DETAIL)
        )

        # assert identifier match
        assert cred_format.attach_id == self.handler.format.api == attachment.ident

        # assert content of attachment is proposal data
        assert attachment.content == LD_PROOF_VC_DETAIL

        # assert data is encoded as base64
        assert attachment.data.base64

    async def test_create_proposal_adds_bbs_context(self):
        cred_ex_record = mock.MagicMock()

        (cred_format, attachment) = await self.handler.create_proposal(
            cred_ex_record, deepcopy(LD_PROOF_VC_DETAIL_BBS)
        )

        # assert BBS url added to context
        assert SECURITY_CONTEXT_BBS_URL in attachment.content["credential"]["@context"]

    async def test_create_proposal_adds_ed25519_2020_context(self):
        cred_ex_record = mock.MagicMock()

        (cred_format, attachment) = await self.handler.create_proposal(
            cred_ex_record, deepcopy(LD_PROOF_VC_DETAIL_ED25519_2020)
        )

        # assert ED25519-2020 url added to context
        assert (
            SECURITY_CONTEXT_ED25519_2020_URL
            in attachment.content["credential"]["@context"]
        )

    async def test_receive_proposal(self):
        cred_ex_record = mock.MagicMock()
        cred_proposal_message = mock.MagicMock()

        # Not much to assert. Receive proposal doesn't do anything
        await self.handler.receive_proposal(cred_ex_record, cred_proposal_message)

    async def test_create_offer(self):
        with (
            mock.patch.object(
                VcLdpManager,
                "assert_can_issue_with_id_and_proof_type",
                mock.CoroutineMock(),
            ) as mock_can_issue,
            patch.object(test_module, "get_properties_without_context", return_value=[]),
        ):
            (cred_format, attachment) = await self.handler.create_offer(
                self.cred_proposal
            )

            mock_can_issue.assert_called_once_with(
                LD_PROOF_VC_DETAIL["credential"]["issuer"],
                LD_PROOF_VC_DETAIL["options"]["proofType"],
            )

        # assert identifier match
        assert cred_format.attach_id == self.handler.format.api == attachment.ident

        # assert content of attachment is proposal data
        assert attachment.content == LD_PROOF_VC_DETAIL

        # assert data is encoded as base64
        assert attachment.data.base64

    async def test_create_offer_adds_bbs_context(self):
        cred_proposal = V20CredProposal(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_PROPOSAL][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            filters_attach=[
                AttachDecorator.data_base64(LD_PROOF_VC_DETAIL_BBS, ident="0")
            ],
        )

        with (
            mock.patch.object(
                VcLdpManager,
                "assert_can_issue_with_id_and_proof_type",
                mock.CoroutineMock(),
            ),
            patch.object(test_module, "get_properties_without_context", return_value=[]),
        ):
            (cred_format, attachment) = await self.handler.create_offer(cred_proposal)

        # assert BBS url added to context
        assert SECURITY_CONTEXT_BBS_URL in attachment.content["credential"]["@context"]

    async def test_create_offer_adds_ed25519_2020_context(self):
        cred_proposal = V20CredProposal(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_PROPOSAL][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            filters_attach=[
                AttachDecorator.data_base64(LD_PROOF_VC_DETAIL_ED25519_2020, ident="0")
            ],
        )

        with (
            mock.patch.object(
                VcLdpManager,
                "assert_can_issue_with_id_and_proof_type",
                mock.CoroutineMock(),
            ),
            patch.object(test_module, "get_properties_without_context", return_value=[]),
        ):
            (cred_format, attachment) = await self.handler.create_offer(cred_proposal)

        # assert BBS url added to context
        assert (
            SECURITY_CONTEXT_ED25519_2020_URL
            in attachment.content["credential"]["@context"]
        )

    async def test_create_offer_x_no_proposal(self):
        with self.assertRaises(V20CredFormatError) as context:
            await self.handler.create_offer(None)
        assert "Cannot create linked data proof offer without proposal data" in str(
            context.exception
        )

    async def test_create_offer_x_wrong_attributes(self):
        missing_properties = ["foo"]
        with (
            mock.patch.object(
                self.manager,
                "assert_can_issue_with_id_and_proof_type",
                mock.CoroutineMock(),
            ),
            patch.object(
                test_module,
                "get_properties_without_context",
                return_value=missing_properties,
            ),
            self.assertRaises(LinkedDataProofException) as context,
        ):
            await self.handler.create_offer(self.cred_proposal)

        assert (
            f"{len(missing_properties)} attributes dropped. "
            f"Provide definitions in context to correct. {missing_properties}"
            in str(context.exception)
        )

    async def test_receive_offer(self):
        cred_ex_record = mock.MagicMock()
        cred_offer_message = mock.MagicMock()

        # Not much to assert. Receive offer doesn't do anything
        await self.handler.receive_offer(cred_ex_record, cred_offer_message)

    async def test_create_bound_request(self):
        cred_offer = V20CredOffer(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_OFFER][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            offers_attach=[AttachDecorator.data_base64(LD_PROOF_VC_DETAIL, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-id",
            state=V20CredExRecord.STATE_OFFER_RECEIVED,
            cred_offer=cred_offer,
        )

        (cred_format, attachment) = await self.handler.create_request(cred_ex_record)

        # assert identifier match
        assert cred_format.attach_id == self.handler.format.api == attachment.ident

        # assert content of attachment is proposal data
        assert attachment.content == LD_PROOF_VC_DETAIL

        # assert data is encoded as base64
        assert attachment.data.base64

    async def test_create_free_request(self):
        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-id",
            state=V20CredExRecord.STATE_OFFER_RECEIVED,
            cred_proposal=self.cred_proposal,
        )

        (cred_format, attachment) = await self.handler.create_request(cred_ex_record)

        # assert identifier match
        assert cred_format.attach_id == self.handler.format.api == attachment.ident

        # assert content of attachment is proposal data
        assert attachment.content == LD_PROOF_VC_DETAIL

        # assert data is encoded as base64
        assert attachment.data.base64

    async def test_create_request_x_no_data(self):
        cred_ex_record = V20CredExRecord(state=V20CredExRecord.STATE_OFFER_RECEIVED)

        with self.assertRaises(V20CredFormatError) as context:
            await self.handler.create_request(cred_ex_record)
        assert (
            "Cannot create linked data proof request without offer or input data"
            in str(context.exception)
        )

    async def test_receive_request_no_offer(self):
        cred_ex_record = mock.MagicMock()
        cred_ex_record.cred_offer = None
        cred_request_message = mock.MagicMock()

        # Not much to assert. Receive request doesn't do anything if no prior offer
        await self.handler.receive_request(cred_ex_record, cred_request_message)

    async def test_receive_request_with_offer_no_id(self):
        cred_offer = V20CredOffer(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_OFFER][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            offers_attach=[AttachDecorator.data_base64(LD_PROOF_VC_DETAIL, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-id",
            state=V20CredExRecord.STATE_OFFER_RECEIVED,
            cred_offer=cred_offer,
        )
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(LD_PROOF_VC_DETAIL, ident="0")],
        )

        await self.handler.receive_request(cred_ex_record, cred_request)

    async def test_receive_request_with_offer_with_id(self):
        detail = deepcopy(LD_PROOF_VC_DETAIL)
        detail["credential"]["credentialSubject"]["id"] = "some id"
        cred_offer = V20CredOffer(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_OFFER][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            offers_attach=[AttachDecorator.data_base64(detail, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-id",
            state=V20CredExRecord.STATE_OFFER_RECEIVED,
            cred_offer=cred_offer,
        )
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(detail, ident="0")],
        )

        await self.handler.receive_request(cred_ex_record, cred_request)

    async def test_receive_request_with_offer_with_id_x_mismatch_id(self):
        detail = deepcopy(LD_PROOF_VC_DETAIL)
        detail["credential"]["credentialSubject"]["id"] = "some id"
        cred_offer = V20CredOffer(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_OFFER][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            offers_attach=[AttachDecorator.data_base64(detail, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-id",
            state=V20CredExRecord.STATE_OFFER_RECEIVED,
            cred_offer=cred_offer,
        )
        req_detail = deepcopy(detail)
        req_detail["credential"]["credentialSubject"]["id"] = "other id"
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(req_detail, ident="0")],
        )

        with self.assertRaises(V20CredFormatError) as context:
            await self.handler.receive_request(cred_ex_record, cred_request)
        assert "must match offer" in str(context.exception)

    async def test_receive_request_with_offer_with_id_x_changed_cred(self):
        detail = deepcopy(LD_PROOF_VC_DETAIL)
        cred_offer = V20CredOffer(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_OFFER][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            offers_attach=[AttachDecorator.data_base64(detail, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-id",
            state=V20CredExRecord.STATE_OFFER_RECEIVED,
            cred_offer=cred_offer,
        )
        req_detail = deepcopy(LD_PROOF_VC_DETAIL_ED25519_2020)
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(req_detail, ident="0")],
        )

        with self.assertRaises(V20CredFormatError) as context:
            await self.handler.receive_request(cred_ex_record, cred_request)
        assert "Request must match offer if offer is sent" in str(context.exception)

    async def test_issue_credential(self):
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(LD_PROOF_VC_DETAIL, ident="0")],
        )

        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-cxid",
            cred_request=cred_request,
        )

        with mock.patch.object(
            VcLdpManager,
            "issue",
            mock.CoroutineMock(
                return_value=VerifiableCredential.deserialize(LD_PROOF_VC)
            ),
        ) as mock_issue:
            (cred_format, attachment) = await self.handler.issue_credential(
                cred_ex_record
            )

            LDProofVCDetail.deserialize(LD_PROOF_VC_DETAIL)

            mock_issue.assert_called_once_with(
                VerifiableCredential.deserialize(LD_PROOF_VC_DETAIL["credential"]),
                LDProofVCOptions.deserialize(LD_PROOF_VC_DETAIL["options"]),
            )

            # assert identifier match
            assert cred_format.attach_id == self.handler.format.api == attachment.ident

            # assert content of attachment is credential data
            assert attachment.content == LD_PROOF_VC

            # assert data is encoded as base64
            assert attachment.data.base64

    async def test_issue_credential_x_no_data(self):
        cred_ex_record = V20CredExRecord()

        with self.assertRaises(V20CredFormatError) as context:
            await self.handler.issue_credential(cred_ex_record)
        assert "Cannot issue credential without credential request" in str(
            context.exception
        )

    async def test_receive_credential(self):
        cred_issue = V20CredIssue(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_ISSUE][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            credentials_attach=[AttachDecorator.data_base64(LD_PROOF_VC, ident="0")],
        )
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(LD_PROOF_VC_DETAIL, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="cred-ex-id",
            cred_request=cred_request,
        )

        await self.handler.receive_credential(cred_ex_record, cred_issue)

    async def test_receive_credential_x_credential_ne_request(self):
        detail = deepcopy(LD_PROOF_VC_DETAIL)

        # Change date so request is different than issued credential
        detail["credential"]["issuanceDate"] = "2020-01-01"

        cred_issue = V20CredIssue(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_ISSUE][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            credentials_attach=[AttachDecorator.data_base64(LD_PROOF_VC, ident="0")],
        )
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(detail, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="cred-ex-id",
            cred_request=cred_request,
        )

        with self.assertRaises(V20CredFormatError) as context:
            await self.handler.receive_credential(cred_ex_record, cred_issue)
        assert "does not match requested credential" in str(context.exception)

    async def test_receive_credential_x_credential_status_ne(self):
        detail = deepcopy(LD_PROOF_VC_DETAIL)

        # Set credential status so it's only set on the detail
        # not the issued credential
        detail["options"]["credentialStatus"] = {"type": "CredentialStatusType"}

        cred_issue = V20CredIssue(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_ISSUE][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            credentials_attach=[AttachDecorator.data_base64(LD_PROOF_VC, ident="0")],
        )
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(detail, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="cred-ex-id",
            cred_request=cred_request,
        )

        with self.assertRaises(V20CredFormatError) as context:
            await self.handler.receive_credential(cred_ex_record, cred_issue)
        assert "Received credential status contains credential status" in str(
            context.exception
        )

    async def test_receive_credential_x_credential_status_ne_both_set(self):
        detail = deepcopy(LD_PROOF_VC_DETAIL)
        status_entry = {"type": "SomeRandomType"}

        # Set credential status in both request and reference credential
        detail["options"]["credentialStatus"] = {"type": "CredentialStatusType"}
        detail["credential"]["credentialStatus"] = deepcopy(status_entry)

        vc = deepcopy(LD_PROOF_VC)
        vc["credentialStatus"] = deepcopy(status_entry)

        cred_issue = V20CredIssue(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_ISSUE][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            credentials_attach=[AttachDecorator.data_base64(vc, ident="0")],
        )
        cred_request = V20CredRequest(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            requests_attach=[AttachDecorator.data_base64(detail, ident="0")],
        )
        cred_ex_record = V20CredExRecord(
            cred_ex_id="cred-ex-id",
            cred_request=cred_request,
        )

        with self.assertRaises(V20CredFormatError) as context:
            await self.handler.receive_credential(cred_ex_record, cred_issue)
        assert "Received credential status type does not match credential request" in str(
            context.exception
        )

    async def test_receive_credential_x_proof_options_ne(self):
        properties = {
            "challenge": "3f9054c0-70df-497d-9bbb-f373ddf986ce",
            "domain": "example.com",
            "proofType": "SomeType",
            "created": "2000-01-11T03:50:55",
        }
        for property, value in properties.items():
            detail = deepcopy(LD_PROOF_VC_DETAIL)

            detail["options"][property] = value

            cred_issue = V20CredIssue(
                formats=[
                    V20CredFormat(
                        attach_id="0",
                        format_=ATTACHMENT_FORMAT[CRED_20_ISSUE][
                            V20CredFormat.Format.LD_PROOF.api
                        ],
                    )
                ],
                credentials_attach=[AttachDecorator.data_base64(LD_PROOF_VC, ident="0")],
            )
            cred_request = V20CredRequest(
                formats=[
                    V20CredFormat(
                        attach_id="0",
                        format_=ATTACHMENT_FORMAT[CRED_20_REQUEST][
                            V20CredFormat.Format.LD_PROOF.api
                        ],
                    )
                ],
                requests_attach=[AttachDecorator.data_base64(detail, ident="0")],
            )
            cred_ex_record = V20CredExRecord(
                cred_ex_id="cred-ex-id",
                cred_request=cred_request,
            )

            with self.assertRaises(V20CredFormatError) as context:
                await self.handler.receive_credential(cred_ex_record, cred_issue)
            assert f"does not match options.{property} from credential request" in str(
                context.exception
            )

    async def test_store_credential(self):
        cred_issue = V20CredIssue(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_ISSUE][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            credentials_attach=[AttachDecorator.data_base64(LD_PROOF_VC, ident="0")],
        )

        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-cxid",
            cred_issue=cred_issue,
        )

        cred_id = "cred_id"
        self.holder.store_credential = mock.CoroutineMock()

        with mock.patch.object(
            VcLdpManager,
            "verify_credential",
            mock.CoroutineMock(return_value=DocumentVerificationResult(verified=True)),
        ):
            await self.handler.store_credential(cred_ex_record, cred_id)

            self.profile.context.injector.get_provider(
                VCHolder
            )._instance.store_credential.assert_called_once_with(
                VCRecord(
                    contexts=LD_PROOF_VC["@context"],
                    expanded_types=[
                        "https://www.w3.org/2018/credentials#VerifiableCredential",
                        "https://example.org/examples#UniversityDegreeCredential",
                    ],
                    issuer_id=LD_PROOF_VC["issuer"],
                    subject_ids=[],
                    schema_ids=[],  # Schemas not supported yet
                    proof_types=[LD_PROOF_VC["proof"]["type"]],
                    cred_value=LD_PROOF_VC,
                    given_id=None,
                    record_id=cred_id,
                )
            )

    async def test_store_credential_x_not_verified(self):
        cred_issue = V20CredIssue(
            formats=[
                V20CredFormat(
                    attach_id="0",
                    format_=ATTACHMENT_FORMAT[CRED_20_ISSUE][
                        V20CredFormat.Format.LD_PROOF.api
                    ],
                )
            ],
            credentials_attach=[AttachDecorator.data_base64(LD_PROOF_VC, ident="0")],
        )

        cred_ex_record = V20CredExRecord(
            cred_ex_id="dummy-cxid",
            cred_issue=cred_issue,
        )

        cred_id = "cred_id"
        self.holder.store_credential = mock.CoroutineMock()

        with (
            mock.patch.object(
                self.manager,
                "_get_suite",
                mock.CoroutineMock(),
            ),
            mock.patch.object(
                self.manager,
                "verify_credential",
                mock.CoroutineMock(
                    return_value=DocumentVerificationResult(verified=False)
                ),
            ),
            mock.patch.object(
                self.manager,
                "_get_proof_purpose",
            ),
            self.assertRaises(V20CredFormatError) as context,
        ):
            await self.handler.store_credential(cred_ex_record, cred_id)
        assert "Received invalid credential: " in str(context.exception)
