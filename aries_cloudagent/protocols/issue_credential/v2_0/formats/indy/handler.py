"""V2.0 issue-credential indy credential format handler."""

import logging

from marshmallow import RAISE
import json
from typing import Mapping, Tuple
import asyncio

from ......cache.base import BaseCache
from ......indy.issuer import IndyIssuer, IndyIssuerRevocationRegistryFullError
from ......indy.holder import IndyHolder, IndyHolderError
from ......indy.sdk.models.cred import IndyCredentialSchema
from ......indy.sdk.models.cred_request import IndyCredRequestSchema
from ......indy.sdk.models.cred_abstract import IndyCredAbstractSchema
from ......ledger.base import BaseLedger
from ......messaging.credential_definitions.util import (
    CRED_DEF_SENT_RECORD_TYPE,
    CredDefQueryStringSchema,
)
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......revocation.models.issuer_rev_reg_record import IssuerRevRegRecord
from ......revocation.models.revocation_registry import RevocationRegistry
from ......revocation.indy import IndyRevocation
from ......storage.base import BaseStorage
from ......storage.error import StorageNotFoundError


from ...message_types import (
    CRED_20_ISSUE,
    CRED_20_OFFER,
    CRED_20_PROPOSAL,
    CRED_20_REQUEST,
)
from ...messages.cred_format import V20CredFormat
from ...messages.cred_proposal import V20CredProposal
from ...messages.cred_offer import V20CredOffer
from ...messages.cred_request import V20CredRequest
from ...messages.cred_issue import V20CredIssue
from ...models.cred_ex_record import V20CredExRecord
from ...models.detail.indy import V20CredExRecordIndy

from ..handler import CredFormatAttachment, V20CredFormatError, V20CredFormatHandler

LOGGER = logging.getLogger(__name__)


class IndyCredFormatHandler(V20CredFormatHandler):
    """Indy credential format handler."""

    format = V20CredFormat.Format.INDY

    @classmethod
    def validate_fields(cls, message_type: str, attachment_data: Mapping):
        """Validate attachment data for a specific message type.

        Uses marshmallow schemas to validate if format specific attachment data
        is valid for the specified message type. Only does structural and type
        checks, does not validate if .e.g. the issuer value is valid.


        Args:
            message_type (str): The message type to validate the attachment data for.
                Should be one of the message types as defined in message_types.py
            attachment_data (Mapping): [description]
                The attachment data to valide

        Raises:
            Exception: When the data is not valid.

        """
        mapping = {
            CRED_20_PROPOSAL: CredDefQueryStringSchema,
            CRED_20_OFFER: IndyCredAbstractSchema,
            CRED_20_REQUEST: IndyCredRequestSchema,
            CRED_20_ISSUE: IndyCredentialSchema,
        }

        # Get schema class
        Schema = mapping[message_type]

        # Validate, throw if not valid
        Schema(unknown=RAISE).load(attachment_data)

    async def _match_sent_cred_def_id(self, tag_query: Mapping[str, str]) -> str:
        """Return most recent matching id of cred def that agent sent to ledger."""

        async with self.profile.session() as session:
            storage = session.inject(BaseStorage)
            found = await storage.find_all_records(
                type_filter=CRED_DEF_SENT_RECORD_TYPE, tag_query=tag_query
            )
        if not found:
            raise V20CredFormatError(
                f"Issuer has no operable cred def for proposal spec {tag_query}"
            )
        return max(found, key=lambda r: int(r.tags["epoch"])).tags["cred_def_id"]

    async def create_proposal(
        self, cred_ex_record: V20CredExRecord, proposal_data: Mapping[str, str]
    ) -> Tuple[V20CredFormat, AttachDecorator]:
        """Create indy credential proposal."""
        if proposal_data is None:
            proposal_data = {}

        return self.get_format_data(CRED_20_PROPOSAL, proposal_data)

    async def receive_proposal(
        self, cred_ex_record: V20CredExRecord, cred_proposal_message: V20CredProposal
    ) -> None:
        """Receive indy credential proposal.

        No custom handling is required for this step.
        """

    async def create_offer(
        self, cred_ex_record: V20CredExRecord, offer_data: Mapping = None
    ) -> CredFormatAttachment:
        """Create indy credential offer."""

        issuer = self.profile.inject(IndyIssuer)
        ledger = self.profile.inject(BaseLedger)
        cache = self.profile.inject(BaseCache, required=False)

        cred_proposal_message = V20CredProposal.deserialize(
            cred_ex_record.cred_proposal
        )

        cred_def_id = await self._match_sent_cred_def_id(
            cred_proposal_message.attachment(self.format)
        )

        async def _create():
            offer_json = await issuer.create_credential_offer(cred_def_id)
            return json.loads(offer_json)

        async with ledger:
            schema_id = await ledger.credential_definition_id2schema_id(cred_def_id)
            schema = await ledger.get_schema(schema_id)
        schema_attrs = {attr for attr in schema["attrNames"]}
        preview_attrs = {
            attr for attr in cred_proposal_message.credential_preview.attr_dict()
        }
        if preview_attrs != schema_attrs:
            raise V20CredFormatError(
                f"Preview attributes {preview_attrs} "
                f"mismatch corresponding schema attributes {schema_attrs}"
            )

        cred_offer = None
        cache_key = f"credential_offer::{cred_def_id}"

        if cache:
            async with cache.acquire(cache_key) as entry:
                if entry.result:
                    cred_offer = entry.result
                else:
                    cred_offer = await _create()
                    await entry.set_result(cred_offer, 3600)
        if not cred_offer:
            cred_offer = await _create()

        return self.get_format_data(CRED_20_OFFER, cred_offer)

    async def receive_offer(
        self, cred_ex_record: V20CredExRecord, cred_offer_message: V20CredOffer
    ) -> None:
        """Receive indy credential offer."""

    async def create_request(
        self, cred_ex_record: V20CredExRecord, request_data: Mapping = None
    ) -> CredFormatAttachment:
        """Create indy credential request."""
        if cred_ex_record.state != V20CredExRecord.STATE_OFFER_RECEIVED:
            raise V20CredFormatError(
                "Indy issue credential format cannot start from credential request"
            )

        await self._check_uniqueness(cred_ex_record.cred_ex_id)

        holder_did = request_data.get("holder_did") if request_data else None
        cred_offer = V20CredOffer.deserialize(cred_ex_record.cred_offer).attachment(
            self.format
        )

        if "nonce" not in cred_offer:
            raise V20CredFormatError("Missing nonce in credential offer")

        nonce = cred_offer["nonce"]
        cred_def_id = cred_offer["cred_def_id"]

        async def _create():
            ledger = self.profile.inject(BaseLedger)
            async with ledger:
                cred_def = await ledger.get_credential_definition(cred_def_id)

            holder = self.profile.inject(IndyHolder)
            request_json, metadata_json = await holder.create_credential_request(
                cred_offer, cred_def, holder_did
            )

            return {
                "request": json.loads(request_json),
                "metadata": json.loads(metadata_json),
            }

        cache_key = f"credential_request::{cred_def_id}::{holder_did}::{nonce}"
        cred_req_result = None
        cache = self.profile.inject(BaseCache, required=False)
        if cache:
            async with cache.acquire(cache_key) as entry:
                if entry.result:
                    cred_req_result = entry.result
                else:
                    cred_req_result = await _create()
                    await entry.set_result(cred_req_result, 3600)
        if not cred_req_result:
            cred_req_result = await _create()

        detail_record = V20CredExRecordIndy(
            cred_ex_id=cred_ex_record.cred_ex_id,
            cred_request_metadata=cred_req_result["metadata"],
        )

        async with self.profile.session() as session:
            await detail_record.save(session, reason="create v2.0 credential request")

        return self.get_format_data(CRED_20_REQUEST, cred_req_result["request"])

    async def receive_request(
        self, cred_ex_record: V20CredExRecord, cred_request_message: V20CredRequest
    ) -> None:
        """Receive indy credential request."""
        if not cred_ex_record.cred_offer:
            raise V20CredFormatError(
                "Indy issue credential format cannot start from credential request"
            )

    async def issue_credential(
        self, cred_ex_record: V20CredExRecord, retries: int = 5
    ) -> CredFormatAttachment:
        """Issue indy credential."""
        await self._check_uniqueness(cred_ex_record.cred_ex_id)

        cred_offer = V20CredOffer.deserialize(cred_ex_record.cred_offer).attachment(
            self.format
        )
        cred_request = V20CredRequest.deserialize(
            cred_ex_record.cred_request
        ).attachment(self.format)

        schema_id = cred_offer["schema_id"]
        cred_def_id = cred_offer["cred_def_id"]

        rev_reg_id = None
        rev_reg = None

        ledger = self.profile.inject(BaseLedger)
        async with ledger:
            schema = await ledger.get_schema(schema_id)
            cred_def = await ledger.get_credential_definition(cred_def_id)

        tails_path = None
        if cred_def["value"].get("revocation"):
            revoc = IndyRevocation(self.profile)
            try:
                active_rev_reg_rec = await revoc.get_active_issuer_rev_reg_record(
                    cred_def_id
                )
                rev_reg = await active_rev_reg_rec.get_registry()
                rev_reg_id = active_rev_reg_rec.revoc_reg_id

                tails_path = rev_reg.tails_local_path
                await rev_reg.get_or_fetch_local_tails_path()

            except StorageNotFoundError:
                async with self.profile.session() as session:
                    posted_rev_reg_recs = await IssuerRevRegRecord.query_by_cred_def_id(
                        session,
                        cred_def_id,
                        state=IssuerRevRegRecord.STATE_POSTED,
                    )
                if not posted_rev_reg_recs:
                    # Send next 2 rev regs, publish tails files in background
                    async with self.profile.session() as session:
                        old_rev_reg_recs = sorted(
                            await IssuerRevRegRecord.query_by_cred_def_id(
                                session,
                                cred_def_id,
                            )
                        )  # prefer to reuse prior rev reg size
                    for _ in range(2):
                        pending_rev_reg_rec = await revoc.init_issuer_registry(
                            cred_def_id,
                            max_cred_num=(
                                old_rev_reg_recs[0].max_cred_num
                                if old_rev_reg_recs
                                else None
                            ),
                        )
                        asyncio.ensure_future(
                            pending_rev_reg_rec.stage_pending_registry(
                                self.profile,
                                max_attempts=3,  # fail both in < 2s at worst
                            )
                        )
                if retries > 0:
                    LOGGER.info(
                        ("Waiting 2s on posted rev reg " "for cred def %s, retrying"),
                        cred_def_id,
                    )
                    await asyncio.sleep(2)
                    return await self.issue_credential(
                        cred_ex_record,
                        retries - 1,
                    )

                raise V20CredFormatError(
                    f"Cred def id {cred_def_id} " "has no active revocation registry"
                )
            del revoc

        cred_values = V20CredOffer.deserialize(
            cred_ex_record.cred_offer
        ).credential_preview.attr_dict(decode=False)
        issuer = self.profile.inject(IndyIssuer)
        try:
            (cred_json, cred_rev_id,) = await issuer.create_credential(
                schema,
                cred_offer,
                cred_request,
                cred_values,
                cred_ex_record.cred_ex_id,
                rev_reg_id,
                tails_path,
            )

            detail_record = V20CredExRecordIndy(
                cred_ex_id=cred_ex_record.cred_ex_id,
                rev_reg_id=rev_reg_id,
                cred_rev_id=cred_rev_id,
            )

            # If the rev reg is now full
            if rev_reg and rev_reg.max_creds == int(cred_rev_id):
                async with self.profile.session() as session:
                    await active_rev_reg_rec.set_state(
                        session,
                        IssuerRevRegRecord.STATE_FULL,
                    )

                # Send next 1 rev reg, publish tails file in background
                revoc = IndyRevocation(self.profile)
                pending_rev_reg_rec = await revoc.init_issuer_registry(
                    active_rev_reg_rec.cred_def_id,
                    max_cred_num=active_rev_reg_rec.max_cred_num,
                )
                asyncio.ensure_future(
                    pending_rev_reg_rec.stage_pending_registry(
                        self.profile,
                        max_attempts=16,
                    )
                )

            async with self.profile.session() as session:
                await detail_record.save(session, reason="v2.0 issue credential")

        except IndyIssuerRevocationRegistryFullError:
            # unlucky: duelling instance issued last cred near same time as us
            async with self.profile.session() as session:
                await active_rev_reg_rec.set_state(
                    session,
                    IssuerRevRegRecord.STATE_FULL,
                )

            if retries > 0:
                # use next rev reg; at worst, lucky instance is putting one up
                LOGGER.info(
                    "Waiting 1s and retrying: revocation registry %s is full",
                    active_rev_reg_rec.revoc_reg_id,
                )
                await asyncio.sleep(1)
                return await self.issue_credential(
                    cred_ex_record,
                    retries - 1,
                )

            raise

        return self.get_format_data(CRED_20_ISSUE, json.loads(cred_json))

    async def receive_credential(
        self, cred_ex_record: V20CredExRecord, cred_issue_message: V20CredIssue
    ) -> None:
        """Receive indy credential.

        Validation is done in the store credential step.
        """

    async def store_credential(
        self, cred_ex_record: V20CredExRecord, cred_id: str = None
    ) -> None:
        """Store indy credential."""
        cred = V20CredIssue.deserialize(cred_ex_record.cred_issue).attachment(
            self.format
        )

        rev_reg_def = None
        ledger = self.profile.inject(BaseLedger)
        async with ledger:
            cred_def = await ledger.get_credential_definition(cred["cred_def_id"])
            if cred.get("rev_reg_id"):
                rev_reg_def = await ledger.get_revoc_reg_def(cred["rev_reg_id"])

        holder = self.profile.inject(IndyHolder)
        cred_offer_message = V20CredOffer.deserialize(cred_ex_record.cred_offer)
        mime_types = None
        if cred_offer_message and cred_offer_message.credential_preview:
            mime_types = cred_offer_message.credential_preview.mime_types() or None

        if rev_reg_def:
            rev_reg = RevocationRegistry.from_definition(rev_reg_def, True)
            await rev_reg.get_or_fetch_local_tails_path()
        try:
            detail_record = await self.get_detail_record(cred_ex_record.cred_ex_id)
            if detail_record is None:
                raise V20CredFormatError(
                    f"No credential exchange {self.format.aries} "
                    f"detail record found for cred ex id {cred_ex_record.cred_ex_id}"
                )
            cred_id_stored = await holder.store_credential(
                cred_def,
                cred,
                detail_record.cred_request_metadata,
                mime_types,
                credential_id=cred_id,
                rev_reg_def=rev_reg_def,
            )

            detail_record.cred_id_stored = cred_id_stored
            detail_record.rev_reg_id = cred.get("rev_reg_id", None)
            detail_record.cred_rev_id = cred.get("cred_rev_id", None)

            async with self.profile.session() as session:
                # Store detail record, emit event
                await detail_record.save(
                    session, reason="store credential v2.0", event=True
                )
        except IndyHolderError as e:
            LOGGER.error(f"Error storing credential: {e.error_code} - {e.message}")
            raise e
