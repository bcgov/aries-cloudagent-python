"""Indy issuer implementation."""

import json
import logging

import indy.anoncreds
from indy.error import ErrorCode, IndyError

from ..storage.indy import IndyStorage
from ..storage.error import StorageError, StorageNotFoundError
from ..storage.record import StorageRecord

from ..wallet.error import WalletNotFoundError

from .base import BaseHolder


class IndyHolder(BaseHolder):
    """Indy holder class."""

    RECORD_TYPE_METADATA = "attribute-metadata"

    def __init__(self, wallet):
        """
        Initialize an IndyHolder instance.

        Args:
            wallet: IndyWallet instance

        """
        self.logger = logging.getLogger(__name__)
        self.wallet = wallet

    async def create_credential_request(
        self, credential_offer, credential_definition, did
    ):
        """
        Create a credential offer for the given credential definition id.

        Args:
            credential_offer: The credential offer to create request for
            credential_definition: The credential definition to create an offer for

        Returns:
            A credential request

        """

        (
            credential_request_json,
            credential_request_metadata_json,
        ) = await indy.anoncreds.prover_create_credential_req(
            self.wallet.handle,
            did,
            json.dumps(credential_offer),
            json.dumps(credential_definition),
            self.wallet.master_secret_id,
        )

        self.logger.debug(
            "Created credential request. "
            + f"credential_request_json={credential_request_json} "
            + f"credential_request_metadata_json={credential_request_metadata_json}"
        )

        credential_request = json.loads(credential_request_json)
        credential_request_metadata = json.loads(credential_request_metadata_json)

        return credential_request, credential_request_metadata

    async def store_credential(
        self, credential_definition, credential_data, credential_request_metadata
    ):
        """
        Store a credential in the wallet.

        Args:
            credential_definition: Credential definition for this credential
            credential_data: Credential data generated by the issuer

        """

        credential_id = await indy.anoncreds.prover_store_credential(
            self.wallet.handle,
            None,  # Always let indy set the id for now
            json.dumps(credential_request_metadata),
            json.dumps(credential_data),
            json.dumps(credential_definition),
            None,  # We don't support revocation yet
        )

        return credential_id

    async def get_credentials(self, start: int, count: int, wql: dict):
        """
        Get credentials stored in the wallet.

        Args:
            start: Starting index
            count: Number of records to return
            wql: wql query dict

        """
        search_handle, record_count = await indy.anoncreds.prover_search_credentials(
            self.wallet.handle, json.dumps(wql)
        )

        # We need to move the database cursor position manually...
        if start > 0:
            # TODO: move cursor in chunks to avoid exploding memory
            await indy.anoncreds.prover_fetch_credentials(search_handle, start)

        credentials_json = await indy.anoncreds.prover_fetch_credentials(
            search_handle, count
        )
        await indy.anoncreds.prover_close_credentials_search(search_handle)

        credentials = json.loads(credentials_json)
        return credentials

    async def get_credentials_for_presentation_request_by_referent(
        self,
        presentation_request: dict,
        referent: str,
        start: int,
        count: int,
        extra_query: dict = {},
    ):
        """
        Get credentials stored in the wallet.

        Args:
            presentation_request: Valid presentation request from issuer
            referent: Presentation request referent to use to search for creds
            start: Starting index
            count: Number of records to return
            extra_query: wql query dict

        """

        search_handle = await indy.anoncreds.prover_search_credentials_for_proof_req(
            self.wallet.handle,
            json.dumps(presentation_request),
            json.dumps(extra_query),
        )

        # We need to move the database cursor position manually...
        if start > 0:
            # TODO: move cursors in chunks to avoid exploding memory
            await indy.anoncreds.prover_fetch_credentials_for_proof_req(
                search_handle, referent, start
            )

        try:
            (
                credentials_json
            ) = await indy.anoncreds.prover_fetch_credentials_for_proof_req(
                search_handle, referent, count
            )
        finally:
            # Always close
            await indy.anoncreds.prover_close_credentials_search_for_proof_req(
                search_handle
            )

        credentials = json.loads(credentials_json)
        return credentials

    async def get_credential(self, credential_id: str):
        """
        Get a credential stored in the wallet.

        Args:
            credential_id: Credential id to retrieve

        """
        try:
            credential_json = await indy.anoncreds.prover_get_credential(
                self.wallet.handle, credential_id
            )
        except IndyError as e:
            if e.error_code == ErrorCode.WalletItemNotFound:
                raise WalletNotFoundError(
                    "Credential not found in the wallet: {}".format(credential_id)
                )
            else:
                raise

        credential = json.loads(credential_json)
        return credential

    async def delete_credential(self, credential_id: str):
        """
        Remove a credential stored in the wallet.

        Args:
            credential_id: Credential id to remove

        """
        try:
            await indy.anoncreds.prover_delete_credential(
                self.wallet.handle, credential_id
            )
        except IndyError as e:
            if e.error_code == ErrorCode.WalletItemNotFound:
                raise WalletNotFoundError(
                    "Credential not found in the wallet: {}".format(credential_id)
                )
            else:
                raise

    async def store_metadata(
        self,
        credential_definition: dict,
        metadata: dict
    ):
        """
        Store MIME type and encoding by attribute for input credential definition.

        Args:
            credential_definition: Credential definition
            metadata: dict mapping attribute name to MIME type (default 'text/plain')
                and encoding

        """
        cred_def_id = credential_definition['id']
        indy_stor = IndyStorage(self.wallet)
        record = StorageRecord(
            type=IndyHolder.RECORD_TYPE_METADATA,
            value=cred_def_id,
            tags={
                attr: json.dumps(
                    {
                        **{'mime-type': 'text/plain'},
                        **(metadata.get(attr))
                    }
                )
                for attr in credential_definition['value']['primary']['r']
                if attr != 'master_secret'
            },
            id=f"{IndyHolder.RECORD_TYPE_METADATA}::{cred_def_id}"
        )

        try:
            existing_record = await indy_stor.get_record(
                IndyHolder.RECORD_TYPE_METADATA,
                f"{IndyHolder.RECORD_TYPE_METADATA}::{cred_def_id}"
            )
            if existing_record.tags == record.tags:
                return  # don't overwrite same data
            await indy_stor.update_record_tags(existing_record, record.tags)
        except StorageNotFoundError:
            await indy_stor.add_record(record)

    async def get_metadata(self, cred_def_id: str, attr: str = None):
        """
        Get MIME type and encoding by for attribute within input cred def id.

        Args:
            cred_def_id: credential definition id
            attr: attribute of interest or omit for all

        """
        try:
            all_meta = await IndyStorage(self.wallet).get_record(
                IndyHolder.RECORD_TYPE_METADATA,
                f"{IndyHolder.RECORD_TYPE_METADATA}::{cred_def_id}"
            )
        except StorageError:
            return None  # no metadata is default position: not an error
        if attr:
            meta_json = all_meta.tags.get(attr)
            if meta_json:
                return json.loads(meta_json)
            raise StorageError(
                f"Attribute {attr} has no tag in metadata record for {cred_def_id}"
            )
        return {attr: json.loads(all_meta.tags[attr]) for attr in all_meta.tags}

    async def create_presentation(
        self,
        presentation_request: dict,
        requested_credentials: dict,
        schemas: dict,
        credential_definitions: dict,
    ):
        """
        Get credentials stored in the wallet.

        Args:
            presentation_request: Valid indy format presentation request
            requested_credentials: Indy format requested_credentials
            schemas: Indy formatted schemas_json
            credential_definitions: Indy formatted schemas_json

        """

        presentation_json = await indy.anoncreds.prover_create_proof(
            self.wallet.handle,
            json.dumps(presentation_request),
            json.dumps(requested_credentials),
            self.wallet.master_secret_id,
            json.dumps(schemas),
            json.dumps(credential_definitions),
            json.dumps({}),  # We don't support revocation currently.
        )

        presentation = json.loads(presentation_json)
        return presentation
