"""Indy-VDR ledger implementation."""

import asyncio
import json
import hashlib
import logging
import os
import os.path
import tempfile

from datetime import datetime, date
from hashlib import sha256
from io import StringIO
from pathlib import Path
from time import time
from typing import Sequence, Tuple

from indy_vdr import ledger, open_pool, Pool, Request, VdrError

from ..cache.base import BaseCache
from ..core.profile import Profile
from ..indy.issuer import IndyIssuer, IndyIssuerError, DEFAULT_CRED_DEF_TAG
from ..messaging.credential_definitions.util import CRED_DEF_SENT_RECORD_TYPE
from ..messaging.schemas.util import SCHEMA_SENT_RECORD_TYPE
from ..storage.base import BaseStorage, StorageRecord
from ..utils import sentinel
from ..utils.env import storage_path
from ..wallet.base import BaseWallet, DIDInfo
from ..wallet.did_posture import DIDPosture

from .base import BaseLedger, Role
from .endpoint_type import EndpointType
from .error import (
    BadLedgerRequestError,
    ClosedPoolError,
    LedgerConfigError,
    LedgerError,
    LedgerTransactionError,
)
from .util import TAA_ACCEPTED_RECORD_TYPE

LOGGER = logging.getLogger(__name__)


def normalize_txns(txns: str) -> str:
    lines = StringIO()
    for line in txns.splitlines():
        line = line.strip()
        if line:
            lines.write(line)
            lines.write("\n")
    return lines.getvalue()


def write_safe(path: Path, content: str):
    dir_path = path.parent
    with tempfile.NamedTemporaryFile(dir=dir_path, delete=False) as tmp:
        tmp.write(content.encode("utf-8"))
        tmp_name = tmp.name
    os.rename(tmp_name, path)


def hash_txns(txns: str) -> str:
    return hashlib.sha256(txns.encode("utf-8")).hexdigest()[-16:]


class IndyVdrLedgerPool:
    """Indy-VDR ledger pool manager."""

    def __init__(
        self,
        name: str,
        *,
        keepalive: int = 0,
        cache: BaseCache = None,
        cache_duration: int = 600,
        genesis_transactions: str = None,
        read_only: bool = False,
    ):
        """
        Initialize an IndyLedger instance.

        Args:
            name: The pool ledger configuration name
            keepalive: How many seconds to keep the ledger open
            cache: The cache instance to use
            cache_duration: The TTL for ledger cache entries
            genesis_transactions: The ledger genesis transaction as a string
            read_only: Prevent any ledger write operations
        """
        self.ref_count = 0
        self.ref_lock = asyncio.Lock()
        self.keepalive = keepalive
        self.close_task: asyncio.Future = None
        self.cache = cache
        self.cache_duration: int = cache_duration
        self.handle: Pool = None
        self.name = name
        self.cfg_path_cache: Path = None
        self.genesis_hash_cache: str = None
        self.genesis_txns_cache = genesis_transactions
        self.init_config = bool(genesis_transactions)
        self.taa_cache: str = None
        self.read_only: bool = read_only

    @property
    def cfg_path(self) -> Path:
        if not self.cfg_path_cache:
            self.cfg_path_cache = storage_path("vdr", create=True)
        return self.cfg_path_cache

    @property
    def genesis_hash(self) -> str:
        if not self.genesis_hash_cache:
            self.genesis_hash_cache = hash_txns(self.genesis_txns)
        return self.genesis_hash_cache

    @property
    def genesis_txns(self) -> str:
        if not self.genesis_txns_cache:
            try:
                path = self.cfg_path.joinpath(self.name, "genesis")
                self.genesis_txns_cache = normalize_txns(open(path).read())
            except FileNotFoundError:
                raise LedgerConfigError(
                    "Pool config '%s' not found", self.name
                ) from None
        return self.genesis_txns_cache

    async def create_pool_config(
        self, genesis_transactions: str, recreate: bool = False
    ):
        """Create the pool ledger configuration."""

        cfg_pool = self.cfg_path.joinpath(self.name)
        cfg_pool.mkdir(exist_ok=True)
        genesis = normalize_txns(genesis_transactions)
        if not genesis:
            raise LedgerConfigError("Empty genesis transactions")

        genesis_path = cfg_pool.joinpath("genesis")
        try:
            cmp_genesis = open(genesis_path).read()
            # FIXME: some normalization wouldn't hurt
            if normalize_txns(cmp_genesis) == genesis:
                LOGGER.debug(
                    "Pool ledger config '%s' is consistent, skipping write",
                    self.name,
                )
                return
            elif not recreate:
                raise LedgerConfigError(
                    f"Pool ledger '{self.name}' exists with "
                    "different genesis transactions"
                )
        except FileNotFoundError:
            pass

        try:
            write_safe(genesis_path, genesis)
        except OSError as err:
            raise LedgerConfigError("Error writing genesis transactions") from err
        LOGGER.debug("Wrote pool ledger config '%s'", self.name)

        self.genesis_txns_cache = genesis

    async def open(self):
        """Open the pool ledger, creating it if necessary."""

        if self.init_config:
            await self.create_pool_config(self.genesis_txns_cache, recreate=True)
            self.init_config = False

        genesis_hash = self.genesis_hash
        cfg_pool = self.cfg_path.joinpath(self.name)
        cfg_pool.mkdir(exist_ok=True)

        cache_path = cfg_pool.joinpath(f"cache-{genesis_hash}")
        try:
            txns = open(cache_path).read()
            cached = True
        except FileNotFoundError:
            txns = self.genesis_txns
            cached = False

        self.handle = await open_pool(transactions=txns)
        upd_txns = normalize_txns(await self.handle.get_transactions())
        if not cached or upd_txns != txns:
            try:
                write_safe(cache_path, upd_txns)
            except OSError:
                LOGGER.exception("Error writing cached genesis transactions")

    async def close(self):
        """Close the pool ledger."""
        if self.handle:
            exc = None
            for attempt in range(3):
                try:
                    self.handle.close()
                except VdrError as err:
                    await asyncio.sleep(0.01)
                    exc = err
                    continue

                self.handle = None
                exc = None
                break

            if exc:
                LOGGER.exception("Exception when closing pool ledger", exc_info=exc)
                self.ref_count += 1  # if we are here, we should have self.ref_lock
                self.close_task = None
                raise LedgerError("Exception when closing pool ledger") from exc

    async def context_open(self):
        """Open the ledger if necessary and increase the number of active references."""
        async with self.ref_lock:
            if self.close_task:
                self.close_task.cancel()
            if not self.handle:
                LOGGER.debug("Opening the pool ledger")
                await self.open()
            self.ref_count += 1

    async def context_close(self):
        """Release the reference and schedule closing of the pool ledger."""

        async def closer(timeout: int):
            """Close the pool ledger after a timeout."""
            await asyncio.sleep(timeout)
            async with self.ref_lock:
                if not self.ref_count:
                    LOGGER.debug("Closing pool ledger after timeout")
                    await self.close()

        async with self.ref_lock:
            self.ref_count -= 1
            if not self.ref_count:
                if self.keepalive:
                    self.close_task = asyncio.ensure_future(closer(self.keepalive))
                else:
                    await self.close()


class IndyVdrLedger(BaseLedger):
    """Indy-VDR ledger class."""

    BACKEND_NAME = "indy-vdr"

    def __init__(
        self,
        pool: IndyVdrLedgerPool,
        profile: Profile,
    ):
        """
        Initialize an IndyVdrLedger instance.

        Args:
            pool: The pool instance handling the raw ledger connection
            profile: The active profile instance
        """
        self.pool = pool
        self.profile = profile

    @property
    def pool_handle(self):
        """Accessor for the ledger pool handle."""
        return self.pool.handle

    @property
    def pool_name(self) -> str:
        """Accessor for the ledger pool name."""
        return self.pool.name

    @property
    def read_only(self) -> bool:
        """Accessor for the ledger read-only flag."""
        return self.pool.read_only

    async def __aenter__(self) -> "IndyVdrLedger":
        """
        Context manager entry.

        Returns:
            The current instance

        """
        await super().__aenter__()
        await self.pool.context_open()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Context manager exit."""
        await self.pool.context_close()
        await super().__aexit__(exc_type, exc, tb)

    async def _submit(
        self,
        request: [str, Request],
        sign: bool = None,
        taa_accept: bool = None,
        sign_did: DIDInfo = sentinel,
    ) -> dict:
        """
        Sign and submit request to ledger.

        Args:
            request_json: The json string to submit
            sign: whether or not to sign the request
            taa_accept: whether to apply TAA acceptance to the (signed, write) request
            sign_did: override the signing DID

        """

        if not self.pool_handle:
            raise ClosedPoolError(
                f"Cannot sign and submit request to closed pool '{self.pool_name}'"
            )

        if isinstance(request, str):
            request = ledger.build_custom_request(request)
        elif not isinstance(request, Request):
            raise BadLedgerRequestError("Expected str or Request")

        if sign is None or sign:
            if sign_did is sentinel:
                sign_did = await self.get_wallet_public_did()
            if sign is None:
                sign = bool(sign_did)

        if sign:
            if not sign_did:
                raise BadLedgerRequestError("Cannot sign request without a public DID")

            if taa_accept or taa_accept is None:
                acceptance = await self.get_latest_txn_author_acceptance()
                if acceptance:
                    request.set_txn_author_agreement_acceptance(acceptance)

            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                request.set_signature(
                    await wallet.sign_message(request.signature_input, sign_did.verkey)
                )
                del wallet

        try:
            request_result = await self.pool.handle.submit_request(request)
        except VdrError as err:
            raise LedgerTransactionError("Ledger request error") from err

        return request_result

    async def create_and_send_schema(
        self,
        issuer: IndyIssuer,
        schema_name: str,
        schema_version: str,
        attribute_names: Sequence[str],
    ) -> Tuple[str, dict]:
        """
        Send schema to ledger.

        Args:
            issuer: The issuer instance creating the schema
            schema_name: The schema name
            schema_version: The schema version
            attribute_names: A list of schema attributes

        """

        public_info = await self.get_wallet_public_did()
        if not public_info:
            raise BadLedgerRequestError("Cannot publish schema without a public DID")

        schema_info = await self.check_existing_schema(
            public_info.did, schema_name, schema_version, attribute_names
        )
        if schema_info:
            LOGGER.warning("Schema already exists on ledger. Returning details.")
            schema_id, schema_def = schema_info
        else:
            if self.read_only:
                raise LedgerError(
                    "Error cannot write schema when ledger is in read only mode"
                )

            try:
                schema_id, schema_json = await issuer.create_schema(
                    public_info.did,
                    schema_name,
                    schema_version,
                    attribute_names,
                )
            except IndyIssuerError as err:
                raise LedgerError(err.message) from err
            schema_def = json.loads(schema_json)

            try:
                schema_req = ledger.build_schema_request(public_info.did, schema_json)
            except VdrError as err:
                raise LedgerError("Exception when building schema request") from err

            try:
                resp = await self._submit(schema_req, True, sign_did=public_info)
                try:
                    # parse sequence number out of response
                    seq_no = resp["txnMetadata"]["seqNo"]
                    schema_def["seqNo"] = seq_no
                except KeyError as err:
                    raise LedgerError(
                        "Failed to parse schema sequence number from ledger response"
                    ) from err
            except LedgerTransactionError as e:
                # Identify possible duplicate schema errors on indy-node < 1.9 and > 1.9
                if (
                    "can have one and only one SCHEMA with name" in e.message
                    or "UnauthorizedClientRequest" in e.message
                ):
                    # handle potential race condition if multiple agents are publishing
                    # the same schema simultaneously
                    schema_info = await self.check_existing_schema(
                        public_info.did, schema_name, schema_version, attribute_names
                    )
                    if schema_info:
                        LOGGER.warning(
                            "Schema already exists on ledger. Returning details."
                            " Error: %s",
                            e,
                        )
                        schema_id, schema_def = schema_info
                else:
                    raise

            schema_id_parts = schema_id.split(":")
            schema_tags = {
                "schema_id": schema_id,
                "schema_issuer_did": public_info.did,
                "schema_name": schema_id_parts[-2],
                "schema_version": schema_id_parts[-1],
                "epoch": str(int(time())),
            }
            record = StorageRecord(SCHEMA_SENT_RECORD_TYPE, schema_id, schema_tags)
            async with self.profile.session() as session:
                storage = session.inject(BaseStorage)
                await storage.add_record(record)

        return schema_id, schema_def

    async def check_existing_schema(
        self,
        public_did: str,
        schema_name: str,
        schema_version: str,
        attribute_names: Sequence[str],
    ) -> Tuple[str, dict]:
        """Check if a schema has already been published."""
        fetch_schema_id = f"{public_did}:2:{schema_name}:{schema_version}"
        schema = await self.fetch_schema_by_id(fetch_schema_id)
        if schema:
            fetched_attrs = schema["attrNames"].copy()
            fetched_attrs.sort()
            cmp_attrs = list(attribute_names)
            cmp_attrs.sort()
            if fetched_attrs != cmp_attrs:
                raise LedgerTransactionError(
                    "Schema already exists on ledger, but attributes do not match: "
                    + f"{schema_name}:{schema_version} {fetched_attrs} != {cmp_attrs}"
                )
            return fetch_schema_id, schema

    async def get_schema(self, schema_id: str) -> dict:
        """
        Get a schema from the cache if available, otherwise fetch from the ledger.

        Args:
            schema_id: The schema id (or stringified sequence number) to retrieve

        """
        if self.pool.cache:
            result = await self.pool.cache.get(f"schema::{schema_id}")
            if result:
                return result

        if schema_id.isdigit():
            return await self.fetch_schema_by_seq_no(int(schema_id))
        else:
            return await self.fetch_schema_by_id(schema_id)

    async def fetch_schema_by_id(self, schema_id: str) -> dict:
        """
        Get schema from ledger.

        Args:
            schema_id: The schema id (or stringified sequence number) to retrieve

        Returns:
            Indy schema dict

        """

        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None

        try:
            schema_req = ledger.build_get_schema_request(public_did, schema_id)
        except VdrError as err:
            raise LedgerError("Exception when building get-schema request") from err

        response = await self._submit(schema_req, sign_did=public_info)

        schema_seqno = response.get("seqNo")
        if not schema_seqno:
            return None  # schema not found

        schema_name = response["data"]["name"]
        schema_version = response["data"]["version"]
        schema_id = f"{response['dest']}:2:{schema_name}:{schema_version}"
        schema_data = {
            "ver": "1.0",
            "id": schema_id,
            "name": schema_name,
            "version": schema_version,
            "attrNames": response["data"]["attr_names"],
            "seqNo": schema_seqno,
        }

        if self.pool.cache:
            await self.pool.cache.set(
                [f"schema::{schema_id}", f"schema::{schema_seqno}"],
                schema_data,
                self.pool.cache_duration,
            )

        return schema_data

    async def fetch_schema_by_seq_no(self, seq_no: int):
        """
        Fetch a schema by its sequence number.

        Args:
            seq_no: schema ledger sequence number

        Returns:
            Indy schema dict

        """
        # get txn by sequence number, retrieve schema identifier components
        try:
            request = ledger.build_get_txn_request(None, None, seq_no=seq_no)
        except VdrError as err:
            raise LedgerError("Exception when building get-txn request") from err

        response = await self._submit(request)

        # transaction data format assumes node protocol >= 1.4 (circa 2018-07)
        data_txn = (response.get("data", {}) or {}).get("txn", {})
        if data_txn.get("type", None) == "101":  # marks indy-sdk schema txn type
            (origin_did, name, version) = (
                data_txn["metadata"]["from"],
                data_txn["data"]["data"]["name"],
                data_txn["data"]["data"]["version"],
            )
            schema_id = f"{origin_did}:2:{name}:{version}"
            return await self.get_schema(schema_id)

        raise LedgerTransactionError(
            f"Could not get schema from ledger for seq no {seq_no}"
        )

    async def create_and_send_credential_definition(
        self,
        issuer: IndyIssuer,
        schema_id: str,
        signature_type: str = None,
        tag: str = None,
        support_revocation: bool = False,
    ) -> Tuple[str, dict, bool]:
        """
        Send credential definition to ledger and store relevant key matter in wallet.

        Args:
            issuer: The issuer instance to use for credential definition creation
            schema_id: The schema id of the schema to create cred def for
            signature_type: The signature type to use on the credential definition
            tag: Optional tag to distinguish multiple credential definitions
            support_revocation: Optional flag to enable revocation for this cred def

        Returns:
            Tuple with cred def id, cred def structure, and whether it's novel

        """
        public_info = await self.get_wallet_public_did()
        if not public_info:
            raise BadLedgerRequestError(
                "Cannot publish credential definition without a public DID"
            )

        schema = await self.get_schema(schema_id)
        if not schema:
            raise LedgerError(f"Ledger {self.pool_name} has no schema {schema_id}")

        novel = False

        # check if cred def is on ledger already
        for test_tag in [tag] if tag else ["tag", DEFAULT_CRED_DEF_TAG]:
            credential_definition_id = issuer.make_credential_definition_id(
                public_info.did, schema, signature_type, test_tag
            )
            ledger_cred_def = await self.fetch_credential_definition(
                credential_definition_id
            )
            if ledger_cred_def:
                LOGGER.warning(
                    "Credential definition %s already exists on ledger %s",
                    credential_definition_id,
                    self.pool_name,
                )

                try:
                    if not await issuer.credential_definition_in_wallet(
                        credential_definition_id
                    ):
                        raise LedgerError(
                            f"Credential definition {credential_definition_id} is on "
                            f"ledger {self.pool_name} but not in wallet "
                            f"{self.profile.name}"
                        )
                except IndyIssuerError as err:
                    raise LedgerError(err.message) from err

                credential_definition_json = json.dumps(ledger_cred_def)
                break
        else:  # no such cred def on ledger
            try:
                if await issuer.credential_definition_in_wallet(
                    credential_definition_id
                ):
                    raise LedgerError(
                        f"Credential definition {credential_definition_id} is in "
                        f"wallet {self.profile.name} but not on ledger {self.pool_name}"
                    )
            except IndyIssuerError as err:
                raise LedgerError(err.message) from err

            # Cred def is neither on ledger nor in wallet: create and send it
            novel = True
            try:
                (
                    credential_definition_id,
                    credential_definition_json,
                ) = await issuer.create_and_store_credential_definition(
                    public_info.did,
                    schema,
                    signature_type,
                    tag,
                    support_revocation,
                )
            except IndyIssuerError as err:
                raise LedgerError(err.message) from err

            if self.read_only:
                raise LedgerError(
                    "Error cannot write cred def when ledger is in read only mode"
                )

            try:
                cred_def_req = ledger.build_cred_def_request(
                    public_info.did, credential_definition_json
                )
            except VdrError as err:
                raise LedgerError("Exception when building cred def request") from err

            await self._submit(cred_def_req, True, sign_did=public_info)

            # Add non-secrets record
            schema_id_parts = schema_id.split(":")
            cred_def_tags = {
                "schema_id": schema_id,
                "schema_issuer_did": schema_id_parts[0],
                "schema_name": schema_id_parts[-2],
                "schema_version": schema_id_parts[-1],
                "issuer_did": public_info.did,
                "cred_def_id": credential_definition_id,
                "epoch": str(int(time())),
            }
            record = StorageRecord(
                CRED_DEF_SENT_RECORD_TYPE, credential_definition_id, cred_def_tags
            )
            async with self.profile.session() as session:
                storage = session.inject(BaseStorage)
                await storage.add_record(record)

        return (credential_definition_id, json.loads(credential_definition_json), novel)

    async def get_credential_definition(self, credential_definition_id: str) -> dict:
        """
        Get a credential definition from the cache if available, otherwise the ledger.

        Args:
            credential_definition_id: The schema id of the schema to fetch cred def for

        """
        if self.pool.cache:
            cache_key = f"credential_definition::{credential_definition_id}"
            async with self.pool.cache.acquire(cache_key) as entry:
                if entry.result:
                    result = entry.result
                else:
                    result = await self.fetch_credential_definition(
                        credential_definition_id
                    )
                    if result:
                        await entry.set_result(result, self.pool.cache_duration)
                return result

        return await self.fetch_credential_definition(credential_definition_id)

    async def fetch_credential_definition(self, credential_definition_id: str) -> dict:
        """
        Get a credential definition from the ledger by id.

        Args:
            credential_definition_id: The cred def id of the cred def to fetch

        """

        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None

        try:
            cred_def_req = ledger.build_get_cred_def_request(
                public_did, credential_definition_id
            )
        except VdrError as err:
            raise LedgerError("Exception when building get-cred-def request") from err

        response = await self._submit(cred_def_req, sign_did=public_info)
        if not response["data"]:
            return None

        schema_id = str(response["ref"])
        signature_type = response["signature_type"]
        tag = response.get("tag", "default")
        origin_did = response["origin"]
        # FIXME: issuer has a method to create a cred def ID
        # may need to qualify the DID
        cred_def_id = f"{origin_did}:3:{signature_type}:{schema_id}:{tag}"

        return {
            "ver": "1.0",
            "id": cred_def_id,
            "schemaId": schema_id,
            "type": signature_type,
            "tag": tag,
            "value": response["data"],
        }

    async def credential_definition_id2schema_id(self, credential_definition_id):
        """
        From a credential definition, get the identifier for its schema.

        Args:
            credential_definition_id: The identifier of the credential definition
                from which to identify a schema
        """

        # scrape schema id or sequence number from cred def id
        tokens = credential_definition_id.split(":")
        if len(tokens) == 8:  # node protocol >= 1.4: cred def id has 5 or 8 tokens
            return ":".join(tokens[3:7])  # schema id spans 0-based positions 3-6

        # get txn by sequence number, retrieve schema identifier components
        seq_no = tokens[3]
        return (await self.get_schema(seq_no))["id"]

    async def get_key_for_did(self, did: str) -> str:
        """Fetch the verkey for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
        """
        nym = self.did_to_nym(did)
        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None
        try:
            nym_req = ledger.build_get_nym_request(public_did, nym)
        except VdrError as err:
            raise LedgerError("Exception when building get-nym request") from err

        response = await self._submit(nym_req, sign_did=public_info)
        data_json = response["data"]
        return json.loads(data_json)["verkey"] if data_json else None

    async def get_all_endpoints_for_did(self, did: str) -> dict:
        """Fetch all endpoints for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
        """
        nym = self.did_to_nym(did)
        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None
        try:
            attrib_req = ledger.build_get_attrib_request(
                public_did, nym, "endpoint", None, None
            )
        except VdrError as err:
            raise LedgerError("Exception when building attribute request") from err

        response = await self._submit(attrib_req, sign_did=public_info)
        data_json = response["data"]

        if data_json:
            endpoints = json.loads(data_json).get("endpoint", None)
        else:
            endpoints = None

        return endpoints

    async def get_endpoint_for_did(
        self, did: str, endpoint_type: EndpointType = None
    ) -> str:
        """Fetch the endpoint for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
            endpoint_type: The type of the endpoint. If none given, returns all
        """

        if not endpoint_type:
            endpoint_type = EndpointType.ENDPOINT
        nym = self.did_to_nym(did)
        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None
        try:
            attrib_req = ledger.build_get_attrib_request(
                public_did, nym, "endpoint", None, None
            )
        except VdrError as err:
            raise LedgerError("Exception when building attribute request") from err

        response = await self._submit(attrib_req, sign_did=public_info)
        data_json = response["data"]
        if data_json:
            endpoint = json.loads(data_json).get("endpoint", None)
            address = endpoint.get(endpoint_type.indy, None) if endpoint else None
        else:
            address = None

        return address

    async def update_endpoint_for_did(
        self, did: str, endpoint: str, endpoint_type: EndpointType = None
    ) -> bool:
        """Check and update the endpoint on the ledger.

        Args:
            did: The ledger DID
            endpoint: The endpoint address
            endpoint_type: The type of the endpoint
        """
        if not endpoint_type:
            endpoint_type = EndpointType.ENDPOINT

        all_exist_endpoints = await self.get_all_endpoints_for_did(did)
        exist_endpoint_of_type = (
            all_exist_endpoints.get(endpoint_type.indy, None)
            if all_exist_endpoints
            else None
        )

        if exist_endpoint_of_type != endpoint:
            if self.read_only:
                raise LedgerError(
                    "Error cannot update endpoint when ledger is in read only mode"
                )

            nym = self.did_to_nym(did)

            if all_exist_endpoints:
                all_exist_endpoints[endpoint_type.indy] = endpoint
                attr_json = json.dumps({"endpoint": all_exist_endpoints})
            else:
                attr_json = json.dumps({"endpoint": {endpoint_type.indy: endpoint}})

            try:
                attrib_req = ledger.build_attrib_request(
                    nym, nym, None, attr_json, None
                )
            except VdrError as err:
                raise LedgerError("Exception when building attribute request") from err

            await self._submit(attrib_req, True, True)
            return True
        return False

    async def register_nym(
        self, did: str, verkey: str, alias: str = None, role: str = None
    ):
        """
        Register a nym on the ledger.

        Args:
            did: DID to register on the ledger.
            verkey: The verification key of the keypair.
            alias: Human-friendly alias to assign to the DID.
            role: For permissioned ledgers, what role should the new DID have.
        """
        if self.read_only:
            raise LedgerError(
                "Error cannot register nym when ledger is in read only mode"
            )

        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None
        try:
            nym_req = ledger.build_nym_request(public_did, did, verkey, alias, role)
        except VdrError as err:
            raise LedgerError("Exception when building nym request") from err

        await self._submit(nym_req)

        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            did_info = await wallet.get_local_did(did)
            metadata = {**did_info.metadata, **DIDPosture.POSTED.metadata}
            await wallet.replace_local_did_metadata(did, metadata)

    async def get_nym_role(self, did: str) -> Role:
        """
        Return the role of the input public DID's NYM on the ledger.

        Args:
            did: DID to query for role on the ledger.
        """
        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None

        try:
            nym_req = ledger.build_get_nym_request(public_did, did)
        except VdrError as err:
            raise LedgerError("Exception when building get-nym request") from err

        response = await self._submit(nym_req)
        nym_data = json.loads(response["data"])
        if not nym_data:
            raise BadLedgerRequestError(f"DID {did} is not public")

        return Role.get(nym_data["role"])

    def nym_to_did(self, nym: str) -> str:
        """Format a nym with the ledger's DID prefix."""
        if nym:
            # remove any existing prefix
            nym = self.did_to_nym(nym)
            return f"did:sov:{nym}"

    async def rotate_public_did_keypair(self, next_seed: str = None) -> None:
        """
        Rotate keypair for public DID: create new key, submit to ledger, update wallet.

        Args:
            next_seed: seed for incoming ed25519 keypair (default random)
        """
        # generate new key
        async with self.profile.transaction() as txn:
            wallet = txn.inject(BaseWallet)
            public_info = await wallet.get_public_did()
            public_did = public_info.did
            verkey = await wallet.rotate_did_keypair_start(public_did, next_seed)
            del wallet
            await txn.commit()

        # submit to ledger (retain role and alias)
        nym = self.did_to_nym(public_did)
        try:
            nym_req = ledger.build_get_nym_request(public_did, nym)
        except VdrError as err:
            raise LedgerError("Exception when building nym request") from err

        response = await self._submit(nym_req)
        data = json.loads(response["data"])
        if not data:
            raise BadLedgerRequestError(
                f"Ledger has no public DID for wallet {self.profile.name}"
            )
        seq_no = data["seqNo"]

        try:
            txn_req = ledger.build_get_txn_request(None, None, seq_no)
        except VdrError as err:
            raise LedgerError("Exception when building get-txn request") from err

        txn_resp = await self._submit(txn_req)
        txn_resp_data = txn_resp["data"]
        if not txn_resp_data:
            raise BadLedgerRequestError(
                f"Bad or missing ledger NYM transaction for DID {public_did}"
            )
        txn_data_data = txn_resp_data["txn"]["data"]
        role_token = Role.get(txn_data_data.get("role")).token()
        alias = txn_data_data.get("alias")
        await self.register_nym(public_did, verkey, role_token, alias)

        # update wallet
        async with self.profile.transaction() as txn:
            wallet = txn.inject(BaseWallet)
            await wallet.rotate_did_keypair_apply(public_did)
            del wallet
            await txn.commit()

    async def get_txn_author_agreement(self, reload: bool = False) -> dict:
        """Get the current transaction author agreement, fetching it if necessary."""
        if not self.pool.taa_cache or reload:
            self.pool.taa_cache = await self.fetch_txn_author_agreement()
        return self.pool.taa_cache

    async def fetch_txn_author_agreement(self) -> dict:
        """Fetch the current AML and TAA from the ledger."""
        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None

        get_aml_req = ledger.build_get_acceptance_mechanisms_request(
            public_did, None, None
        )
        response = await self._submit(get_aml_req, sign_did=public_info)
        aml_found = response["data"]

        get_taa_req = ledger.build_get_txn_author_agreement_request(public_did, None)
        response = await self._submit(get_taa_req, sign_did=public_info)
        taa_found = response["data"]
        taa_required = bool(taa_found and taa_found["text"])
        if taa_found:
            taa_found["digest"] = self.taa_digest(
                taa_found["version"], taa_found["text"]
            )

        return {
            "aml_record": aml_found,
            "taa_record": taa_found,
            "taa_required": taa_required,
        }

    def taa_rough_timestamp(self) -> int:
        """Get a timestamp accurate to the day.

        Anything more accurate is a privacy concern.
        """
        return int(datetime.combine(date.today(), datetime.min.time()).timestamp())

    def taa_digest(self, version: str, text: str):
        """Generate the digest of a TAA record."""
        if not version or not text:
            raise ValueError("Bad input for TAA digest")
        taa_plaintext = version + text
        return sha256(taa_plaintext.encode("utf-8")).digest().hex()

    async def accept_txn_author_agreement(
        self, taa_record: dict, mechanism: str, accept_time: int = None
    ):
        """Save a new record recording the acceptance of the TAA."""
        if not accept_time:
            accept_time = self.taa_rough_timestamp()
        acceptance = {
            "text": taa_record["text"],
            "version": taa_record["version"],
            "digest": taa_record["digest"],
            "mechanism": mechanism,
            "time": accept_time,
        }
        record = StorageRecord(
            TAA_ACCEPTED_RECORD_TYPE,
            json.dumps(acceptance),
            {"pool_name": self.pool_name},
        )
        async with self.profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(record)
        if self.pool.cache:
            cache_key = TAA_ACCEPTED_RECORD_TYPE + "::" + self.pool_name
            await self.pool.cache.set(cache_key, acceptance, self.pool.cache_duration)

    async def get_latest_txn_author_acceptance(self) -> dict:
        """Look up the latest TAA acceptance."""
        cache_key = TAA_ACCEPTED_RECORD_TYPE + "::" + self.pool_name
        acceptance = self.pool.cache and await self.pool.cache.get(cache_key)
        if not acceptance:
            tag_filter = {"pool_name": self.pool_name}
            async with self.profile.session() as session:
                storage = session.inject(BaseStorage)
                found = await storage.find_all_records(
                    TAA_ACCEPTED_RECORD_TYPE, tag_filter
                )
            if found:
                records = list(json.loads(record.value) for record in found)
                records.sort(key=lambda v: v["time"], reverse=True)
                acceptance = records[0]
            else:
                acceptance = {}
            if self.pool.cache:
                await self.pool.cache.set(
                    cache_key, acceptance, self.pool.cache_duration
                )
        return acceptance

    async def get_revoc_reg_def(self, revoc_reg_id: str) -> dict:
        """Get revocation registry definition by ID."""
        public_info = await self.get_wallet_public_did()
        try:
            fetch_req = ledger.build_get_revoc_reg_def_request(
                public_info and public_info.did, revoc_reg_id
            )
            response = await self._submit(fetch_req, sign_did=public_info)
        except VdrError as err:
            raise LedgerError(
                f"get_revoc_reg_def failed for revoc_reg_id='{revoc_reg_id}'"
            ) from err

        revoc_reg_def = response["result"]["data"]
        revoc_reg_def["ver"] = "1.0"

        assert revoc_reg_def.get("id") == revoc_reg_id
        return revoc_reg_def

    async def get_revoc_reg_entry(
        self, revoc_reg_id: str, timestamp: int
    ) -> (dict, int):
        """Get revocation registry entry by revocation registry ID and timestamp."""
        public_info = await self.get_wallet_public_did()
        try:
            fetch_req = ledger.build_get_revoc_reg_request(
                public_info and public_info.did, revoc_reg_id, timestamp
            )
            response = await self._submit(fetch_req, sign_did=public_info)
        except VdrError as err:
            raise LedgerError(
                f"get_revoc_reg_entry failed for revoc_reg_id='{revoc_reg_id}'"
            ) from err

        reg_entry = {
            "ver": "1.0",
            "value": response["result"]["data"]["value"],
        }
        ledger_timestamp = response["result"]["data"]["txnTime"]
        assert response["result"]["data"]["revocRegDefId"] == revoc_reg_id
        return reg_entry, ledger_timestamp

    async def get_revoc_reg_delta(
        self, revoc_reg_id: str, timestamp_from=0, timestamp_to=None
    ) -> (dict, int):
        """
        Look up a revocation registry delta by ID.

        :param revoc_reg_id revocation registry id
        :param timestamp_from from time. a total number of seconds from Unix Epoch
        :param timestamp_to to time. a total number of seconds from Unix Epoch

        :returns delta response, delta timestamp
        """
        if timestamp_to is None:
            timestamp_to = int(time())
        public_info = await self.get_wallet_public_did()
        try:
            fetch_req = ledger.build_get_revoc_reg_delta_request(
                public_info and public_info.did,
                revoc_reg_id,
                timestamp_from,
                timestamp_to,
            )
            response = await self._submit(fetch_req, sign_did=public_info)
        except VdrError as err:
            raise LedgerError(
                f"get_revoc_reg_delta failed for revoc_reg_id='{revoc_reg_id}'"
            ) from err

        reg_delta = {
            "ver": "1.0",
            "value": response["result"]["data"]["value"]["accum_to"]["value"],
        }
        delta_timestamp = response["result"]["data"]["txnTime"]
        assert response["result"]["data"]["revocRegDefId"] == revoc_reg_id
        return reg_delta, delta_timestamp

    async def send_revoc_reg_def(self, revoc_reg_def: dict, issuer_did: str = None):
        """Publish a revocation registry definition to the ledger."""
        # NOTE - issuer DID could be extracted from the revoc_reg_def ID
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            if issuer_did:
                did_info = await wallet.get_local_did(issuer_did)
            else:
                did_info = await wallet.get_public_did()
            del wallet
        if not did_info:
            raise LedgerTransactionError(
                "No issuer DID found for revocation registry definition"
            )
        try:
            request_json = ledger.build_revoc_reg_def_request(
                did_info.did, json.dumps(revoc_reg_def)
            )
        except VdrError as err:
            raise LedgerError(
                "Exception when sending revocation registry definition"
            ) from err

        await self._submit(request_json, True, True, did_info)

    async def send_revoc_reg_entry(
        self,
        revoc_reg_id: str,
        revoc_def_type: str,
        revoc_reg_entry: dict,
        issuer_did: str = None,
    ):
        """Publish a revocation registry entry to the ledger."""
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            if issuer_did:
                did_info = await wallet.get_local_did(issuer_did)
            else:
                did_info = await wallet.get_public_did()
            del wallet
        if not did_info:
            raise LedgerTransactionError(
                "No issuer DID found for revocation registry entry"
            )
        try:
            request_json = ledger.build_revoc_reg_entry_request(
                did_info.did, revoc_reg_id, revoc_def_type, json.dumps(revoc_reg_entry)
            )
        except VdrError as err:
            raise LedgerError(
                "Exception when sending revocation registry entry"
            ) from err
        await self._submit(request_json, True, True, did_info)

    async def get_wallet_public_did(self) -> DIDInfo:
        """Fetch the public DID from the wallet."""
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            return await wallet.get_public_did()
