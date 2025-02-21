"""Indy-VDR ledger implementation."""

import asyncio
import hashlib
import json
import logging
import os
import os.path
import tempfile
from datetime import date, datetime, timezone
from io import StringIO
from pathlib import Path
from time import time
from typing import Dict, List, Optional, Tuple, Union

from indy_vdr import Pool, Request, VdrError, ledger, open_pool

from ..cache.base import BaseCache
from ..core.profile import Profile
from ..messaging.valid import IndyDID
from ..storage.base import BaseStorage, StorageRecord
from ..utils import sentinel
from ..utils.env import storage_path
from ..wallet.base import BaseWallet, DIDInfo
from ..wallet.did_posture import DIDPosture
from ..wallet.error import WalletNotFoundError
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


def _normalize_txns(txns: str) -> str:
    """Normalize a set of genesis transactions."""
    LOGGER.debug("Normalizing genesis transactions")
    lines = StringIO()
    for line in txns.splitlines():
        line = line.strip()
        if line:
            lines.write(line)
            lines.write("\n")
    LOGGER.debug("Finished normalizing genesis transactions")
    return lines.getvalue()


def _write_safe(path: Path, content: str):
    """Atomically write to a file path."""
    LOGGER.debug("Writing content safely to path: %s", path)
    dir_path = path.parent
    with tempfile.NamedTemporaryFile(dir=dir_path, delete=False) as tmp:
        LOGGER.debug("Created temporary file: %s", tmp.name)
        tmp.write(content.encode("utf-8"))
        tmp_name = tmp.name
    LOGGER.debug("Renaming temporary file to target path")
    os.rename(tmp_name, path)
    LOGGER.debug("Successfully wrote content to: %s", path)


def _hash_txns(txns: str) -> str:
    """Obtain a hash of a set of genesis transactions."""
    LOGGER.debug("Calculating hash of genesis transactions")
    hash_value = hashlib.sha256(txns.encode("utf-8")).hexdigest()[-16:]
    LOGGER.debug("Generated transaction hash: %s", hash_value)
    return hash_value


class IndyVdrLedgerPool:
    """Indy-VDR ledger pool manager with singleton behavior based on configuration."""

    _instances: Dict[tuple, "IndyVdrLedgerPool"] = {}
    _lock = asyncio.Lock()

    def __init__(
        self,
        *,
        name: str,
        keepalive: int = 0,
        cache: Optional[BaseCache] = None,
        cache_duration: int = 600,
        genesis_transactions: Optional[str] = None,
        read_only: bool = False,
        socks_proxy: Optional[str] = None,
    ):
        """Private constructor. Use 'get_or_create' to instantiate."""
        # Instance attributes
        self.name = name
        self.keepalive = keepalive
        self.cache = cache
        self.cache_duration = cache_duration
        self.genesis_transactions = genesis_transactions
        self.read_only = read_only
        self.socks_proxy = socks_proxy

        self.handle: Optional[Pool] = None
        self.taa_cache: Optional[str] = None

        self._ref_count = 0
        self._ref_lock = asyncio.Lock()
        self._close_task: Optional[asyncio.Task] = None
        self._cfg_path_cache: Optional[Path] = None
        self._genesis_hash_cache: Optional[str] = None
        self._genesis_txns_cache = genesis_transactions
        self._init_config = bool(genesis_transactions)

    @classmethod
    async def get_or_create(
        cls,
        *,
        name: str,
        keepalive: int = 0,
        cache: Optional[BaseCache] = None,
        cache_duration: int = 600,
        genesis_transactions: Optional[str] = None,
        read_only: bool = False,
        socks_proxy: Optional[str] = None,
    ) -> "IndyVdrLedgerPool":
        """Asynchronously get or create a singleton instance based on configuration.

        Args:
            name: The pool ledger configuration name.
            keepalive: How many seconds to keep the ledger open.
            cache: The cache instance to use.
            cache_duration: The TTL for ledger cache entries.
            genesis_transactions: The ledger genesis transaction as a string.
            read_only: Prevent any ledger write operations.
            socks_proxy: Specifies socks proxy for ZMQ to connect to ledger pool.

        Returns:
            An initialized instance of IndyVdrLedgerPool.
        """
        LOGGER.debug(
            "Creating or retrieving IndyVdrLedgerPool instance with params: name=%s, "
            "keepalive=%s, cache_duration=%s, read_only=%s",
            name,
            keepalive,
            cache_duration,
            read_only,
        )

        config_key = (
            name,
            keepalive,
            cache_duration,
            genesis_transactions,
            read_only,
            socks_proxy,
        )
        async with cls._lock:
            if config_key not in cls._instances:
                LOGGER.debug(
                    "No existing instance found for config key, creating new instance"
                )
                ledger_pool_instance = cls(
                    name=name,
                    keepalive=keepalive,
                    cache=cache,
                    cache_duration=cache_duration,
                    genesis_transactions=genesis_transactions,
                    read_only=read_only,
                    socks_proxy=socks_proxy,
                )
                try:
                    LOGGER.debug("Initializing new IndyVdrLedgerPool instance")
                    await ledger_pool_instance._initialize()
                except Exception as e:
                    LOGGER.error(
                        "Initialization failed for IndyVdrLedgerPool with config: %s\n%s",
                        config_key,
                        e,
                    )
                    raise
                cls._instances[config_key] = ledger_pool_instance
                LOGGER.debug(
                    "Successfully created new IndyVdrLedgerPool instance with name %s",
                    name,
                )
            else:
                LOGGER.debug(
                    "Found existing IndyVdrLedgerPool instance with name %s", name
                )
                ledger_pool_instance = cls._instances[config_key]
                await ledger_pool_instance._cancel_close_task()

        return ledger_pool_instance

    async def _initialize(self) -> None:
        """Initialize the ledger pool."""
        LOGGER.debug("Beginning pool initialization")
        if self._init_config:
            LOGGER.debug("Creating pool config with genesis transactions")
            await self._create_pool_config(self._genesis_txns_cache, recreate=True)
            self._init_config = False
        LOGGER.debug("Opening pool connection")
        await self._open()
        LOGGER.debug("Pool initialization complete")

    @classmethod
    async def release_instance(cls, instance: "IndyVdrLedgerPool") -> None:
        """Release a reference to the instance and possibly remove it from the registry.

        Args:
            instance: The IndyVdrLedgerPool instance to release.
        """
        LOGGER.debug("Beginning instance release process for pool: %s", instance.name)

        config_key = (
            instance.name,
            instance.keepalive,
            instance.cache_duration,
            instance.genesis_transactions,
            instance.read_only,
            instance.socks_proxy,
        )
        async with cls._lock:
            if instance._ref_count <= 0:
                LOGGER.debug("Reference count is empty, cleaning up instance")
                await instance._close()
                del cls._instances[config_key]
                LOGGER.debug(
                    "Successfully removed IndyVdrLedgerPool instance with name %s",
                    instance.name,
                )
            else:
                LOGGER.debug(
                    "Instance %s still has active references: %s",
                    instance.name,
                    instance._ref_count,
                )

    @property
    def cfg_path(self) -> Path:
        """Get the path to the configuration file, ensuring it's created."""
        if not self._cfg_path_cache:
            LOGGER.debug("Creating configuration path cache")
            self._cfg_path_cache = storage_path("vdr", create=True)
            LOGGER.debug("Configuration path set to: %s", self._cfg_path_cache)
        return self._cfg_path_cache

    @property
    def genesis_hash(self) -> str:
        """Get the hash of the configured genesis transactions."""
        if not self._genesis_hash_cache:
            LOGGER.debug("Calculating genesis transactions hash")
            self._genesis_hash_cache = _hash_txns(self.genesis_txns)
            LOGGER.debug("Genesis hash calculated: %s", self._genesis_hash_cache)
        return self._genesis_hash_cache

    @property
    def genesis_txns(self) -> str:
        """Get the configured genesis transactions."""
        if not self._genesis_txns_cache:
            LOGGER.debug("Loading genesis transactions from file")
            try:
                path = self.cfg_path.joinpath(self.name, "genesis")
                LOGGER.debug("Reading genesis file from: %s", path)
                self._genesis_txns_cache = _normalize_txns(open(path).read())
                LOGGER.debug("Successfully loaded genesis transactions")
            except FileNotFoundError:
                LOGGER.error("Pool config '%s' not found", self.name)
                raise LedgerConfigError("Pool config '%s' not found", self.name) from None
        return self._genesis_txns_cache

    async def _create_pool_config(
        self, genesis_transactions: str, recreate: bool = False
    ) -> None:
        """Create the pool ledger configuration."""
        LOGGER.debug("Creating pool config for '%s', recreate=%s", self.name, recreate)

        cfg_pool = self.cfg_path.joinpath(self.name)
        cfg_pool.mkdir(exist_ok=True)
        LOGGER.debug("Created pool configuration directory: %s", cfg_pool)

        genesis = _normalize_txns(genesis_transactions)
        if not genesis:
            LOGGER.error("Empty genesis transactions provided")
            raise LedgerConfigError("Empty genesis transactions")

        genesis_path = cfg_pool.joinpath("genesis")
        try:
            LOGGER.debug("Checking existing genesis file: %s", genesis_path)
            cmp_genesis = open(genesis_path).read()
            if _normalize_txns(cmp_genesis) == genesis:
                LOGGER.debug(
                    "Pool ledger config '%s' is consistent, skipping write",
                    self.name,
                )
                return
            elif not recreate:
                LOGGER.error(
                    "Pool ledger '%s' exists with different genesis transactions",
                    self.name,
                )
                raise LedgerConfigError(
                    f"Pool ledger '{self.name}' exists with "
                    "different genesis transactions"
                )
        except FileNotFoundError:
            LOGGER.debug("No existing genesis file found")
            pass

        try:
            LOGGER.debug("Writing genesis transactions to: %s", genesis_path)
            _write_safe(genesis_path, genesis)
        except OSError as err:
            LOGGER.exception("Error writing genesis transactions", exc_info=err)
            raise LedgerConfigError("Error writing genesis transactions") from err
        LOGGER.debug("Successfully wrote pool ledger config '%s'", self.name)

        self._genesis_txns_cache = genesis

    async def _open(self) -> None:
        """Open the pool ledger, creating it if necessary."""
        LOGGER.debug("Opening pool ledger: %s", self.name)

        if self._init_config:
            LOGGER.debug("Initializing pool config with genesis transactions")
            await self._create_pool_config(self._genesis_txns_cache, recreate=True)
            self._init_config = False

        genesis_hash = self.genesis_hash
        LOGGER.debug("Using genesis hash: %s", genesis_hash)
        cfg_pool = self.cfg_path.joinpath(self.name)
        cfg_pool.mkdir(exist_ok=True)

        cache_path = cfg_pool.joinpath(f"cache-{genesis_hash}")
        try:
            LOGGER.debug("Attempting to read cached transactions from: %s", cache_path)
            txns = open(cache_path).read()
            cached = True
            LOGGER.debug("Successfully read cached transactions")
        except FileNotFoundError:
            LOGGER.debug("No cached transactions found, using genesis transactions")
            txns = self.genesis_txns
            cached = False

        LOGGER.debug("Opening pool with transactions, socks_proxy=%s", self.socks_proxy)
        self.handle = await open_pool(transactions=txns, socks_proxy=self.socks_proxy)
        LOGGER.debug("Pool opened successfully")

        upd_txns = _normalize_txns(await self.handle.get_transactions())
        if not cached or upd_txns != txns:
            LOGGER.debug("Updating cached transactions")
            try:
                _write_safe(cache_path, upd_txns)
                LOGGER.debug("Successfully wrote updated cached transactions")
            except OSError:
                LOGGER.exception("Error writing cached genesis transactions")

    async def context_open(self) -> None:
        """Open the ledger if necessary and increase the number of active references."""
        await self._cancel_close_task()
        async with self._ref_lock:
            if not self.handle:
                LOGGER.debug("Opening the pool ledger")
                await self._open()
            self._ref_count += 1
            LOGGER.debug(
                "Incremented reference count to %s for instance %s",
                self._ref_count,
                self.name,
            )

    async def _close(self) -> None:
        """Close the pool ledger."""
        if self.handle:
            LOGGER.debug("Attempting to close pool ledger")
            exc = None
            for attempt in range(3):
                try:
                    LOGGER.debug("Close attempt %s/3", attempt + 1)
                    self.handle.close()
                except VdrError as err:
                    LOGGER.warning(
                        "Error closing pool ledger (attempt %s/3): %s",
                        attempt + 1,
                        str(err),
                    )
                    await asyncio.sleep(0.01)
                    exc = err
                    continue

                self.handle = None
                exc = None
                LOGGER.debug("Successfully closed pool ledger")
                break

            if exc:
                LOGGER.exception(
                    "Failed to close pool ledger after 3 attempts", exc_info=exc
                )
                self._ref_count += 1  # if we are here, we should have self.ref_lock
                LOGGER.debug(
                    "Re-incremented reference count to %s for instance %s",
                    self._ref_count,
                    self.name,
                )
                self._close_task = None
                raise LedgerError("Exception when closing pool ledger") from exc

    async def context_close(self) -> None:
        """Release the reference and schedule closing of the pool ledger."""
        LOGGER.debug("Context close called for pool %s", self.name)

        async def _keepalive_closer(timeout: int) -> None:
            """Close the pool ledger after a timeout."""
            try:
                LOGGER.debug(
                    "Coroutine will sleep for %d seconds before closing the pool.",
                    timeout,
                )
                await asyncio.sleep(timeout)

                await IndyVdrLedgerPool.release_instance(self)
            except Exception as e:
                LOGGER.error(
                    "Exception occurred in closer coroutine during pool closure: %s",
                    e,
                )

        async with self._ref_lock:
            self._ref_count -= 1
            LOGGER.debug(
                "Decremented ref_count to %d for instance %s",
                self._ref_count,
                self.name,
            )
            if self._ref_count <= 0:
                if self.keepalive:
                    LOGGER.debug(
                        "Scheduling closer coroutine with keepalive=%s",
                        self.keepalive,
                    )
                    self._close_task = asyncio.create_task(
                        _keepalive_closer(self.keepalive)
                    )
                else:
                    LOGGER.debug(
                        "No keepalive set. Proceeding to close the pool immediately."
                    )
                    await IndyVdrLedgerPool.release_instance(self)

    async def _cancel_close_task(self) -> None:
        """Cancel any pending close task."""
        async with self._ref_lock:
            if self._close_task:
                self._close_task.cancel()
                self._close_task = None


class IndyVdrLedger(BaseLedger):
    """Indy-VDR ledger class."""

    BACKEND_NAME = "indy-vdr"

    def __init__(
        self,
        pool: IndyVdrLedgerPool,
        profile: Profile,
    ):
        """Initialize an IndyVdrLedger instance.

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

    async def is_ledger_read_only(self) -> bool:
        """Check if ledger is read-only including TAA."""
        if self.read_only:
            return self.read_only
        # if TAA is required and not accepted we should be in read-only mode
        taa = await self.get_txn_author_agreement()
        if taa["taa_required"]:
            taa_acceptance = await self.get_latest_txn_author_acceptance()
            if "mechanism" not in taa_acceptance:
                return True
        return self.read_only

    async def __aenter__(self) -> "IndyVdrLedger":
        """Context manager entry.

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
        request: Union[str, Request],
        sign: Optional[bool] = None,
        taa_accept: Optional[bool] = None,
        sign_did: DIDInfo = sentinel,
        write_ledger: bool = True,
    ) -> dict:
        """Sign and submit request to ledger.

        Args:
            request: The request to submit
            sign: whether or not to sign the request
            taa_accept: whether to apply TAA acceptance to the (signed, write) request
            sign_did: override the signing DID
            write_ledger: whether to write the request to the ledger

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
                    acceptance = {
                        "taaDigest": acceptance["digest"],
                        "mechanism": acceptance["mechanism"],
                        "time": acceptance["time"],
                    }
                    request.set_txn_author_agreement_acceptance(acceptance)

            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                request.set_signature(
                    await wallet.sign_message(request.signature_input, sign_did.verkey)
                )
                del wallet

        if not write_ledger:
            return json.loads(request.body)

        try:
            request_result = await self.pool.handle.submit_request(request)
        except VdrError as err:
            raise LedgerTransactionError("Ledger request error") from err

        return request_result

    async def _create_schema_request(
        self,
        public_info: DIDInfo,
        schema_json: str,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
    ):
        """Create the ledger request for publishing a schema."""
        try:
            schema_req = ledger.build_schema_request(public_info.did, schema_json)
        except VdrError as err:
            raise LedgerError("Exception when building schema request") from err

        if endorser_did and not write_ledger:
            schema_req.set_endorser(endorser_did)

        return schema_req

    async def _create_revoc_reg_def_request(
        self,
        public_info: DIDInfo,
        revoc_reg_def_json: str,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
    ):
        """Create the ledger request for publishing a revocation registry definition."""
        try:
            revoc_reg_def_req = ledger.build_revoc_reg_def_request(
                public_info.did, revoc_reg_def_json
            )
        except VdrError as err:
            raise LedgerError("Exception when building revoc reg def request") from err

        if endorser_did and not write_ledger:
            revoc_reg_def_req.set_endorser(endorser_did)

        return revoc_reg_def_req

    async def _create_revoc_reg_entry_request(
        self,
        public_info: DIDInfo,
        revoc_reg_def_id: str,
        revoc_def_type: str,
        revoc_reg_entry_json: str,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
    ):
        """Create the ledger request for publishing a revocation registry definition."""
        try:
            revoc_reg_entry_request = ledger.build_revoc_reg_entry_request(
                public_info.did, revoc_reg_def_id, revoc_def_type, revoc_reg_entry_json
            )
        except VdrError as err:
            raise LedgerError("Exception when building revoc reg def request") from err

        if endorser_did and not write_ledger:
            revoc_reg_entry_request.set_endorser(endorser_did)

        return revoc_reg_entry_request

    async def get_schema(self, schema_id: str) -> dict:
        """Get a schema from the cache if available, otherwise fetch from the ledger.

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
        """Get schema from ledger.

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

    async def fetch_schema_by_seq_no(self, seq_no: int) -> dict:
        """Fetch a schema by its sequence number.

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

    async def _create_credential_definition_request(
        self,
        public_info: DIDInfo,
        credential_definition_json: str,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
    ):
        """Create the ledger request for publishing a credential definition."""
        try:
            cred_def_req = ledger.build_cred_def_request(
                public_info.did, credential_definition_json
            )
        except VdrError as err:
            raise LedgerError("Exception when building cred def request") from err

        if endorser_did and not write_ledger:
            cred_def_req.set_endorser(endorser_did)

        return cred_def_req

    async def get_credential_definition(self, credential_definition_id: str) -> dict:
        """Get a credential definition from the cache if available, otherwise the ledger.

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
        """Get a credential definition from the ledger by id.

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
        """From a credential definition, get the identifier for its schema.

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

    async def get_key_for_did(self, did: str) -> Optional[str]:
        """Fetch the verkey for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
        """
        nym = self.did_to_nym(did)
        public_info = await self.get_wallet_public_did()
        public_did = public_info.did if public_info else None

        # current public_did may be non-indy -> create nym request with empty public did
        if public_did is not None and not bool(IndyDID.PATTERN.match(public_did)):
            public_did = None

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
        self, did: str, endpoint_type: Optional[EndpointType] = None
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
        self,
        did: str,
        endpoint: str,
        endpoint_type: Optional[EndpointType] = None,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
        routing_keys: Optional[List[str]] = None,
    ) -> bool:
        """Check and update the endpoint on the ledger.

        Args:
            did: The ledger DID
            endpoint: The endpoint address
            endpoint_type: The type of the endpoint
            write_ledger: Whether to write the endpoint to the ledger
            endorser_did: DID of the endorser to use for the transaction
            routing_keys: List of routing keys
        """
        public_info = await self.get_wallet_public_did()
        if not public_info:
            raise BadLedgerRequestError(
                "Cannot update endpoint at ledger without a public DID"
            )

        if not endpoint_type:
            endpoint_type = EndpointType.ENDPOINT

        all_exist_endpoints = await self.get_all_endpoints_for_did(did)
        exist_endpoint_of_type = (
            all_exist_endpoints.get(endpoint_type.indy, None)
            if all_exist_endpoints
            else None
        )
        existing_routing_keys = (
            all_exist_endpoints.get("routingKeys") if all_exist_endpoints else None
        )

        if exist_endpoint_of_type != endpoint or existing_routing_keys != routing_keys:
            if self.read_only:
                raise LedgerError(
                    "Error cannot update endpoint when ledger is in read only mode"
                )

            nym = self.did_to_nym(did)

            attr_json = await self._construct_attr_json(
                endpoint, endpoint_type, all_exist_endpoints, routing_keys
            )

            try:
                attrib_req = ledger.build_attrib_request(nym, nym, None, attr_json, None)

                if endorser_did and not write_ledger:
                    attrib_req.set_endorser(endorser_did)
                    resp = await self._submit(
                        attrib_req,
                        True,
                        sign_did=public_info,
                        write_ledger=write_ledger,
                    )
                    if not write_ledger:
                        return {"signed_txn": resp}

            except VdrError as err:
                raise LedgerError("Exception when building attribute request") from err

            await self._submit(attrib_req, True, True)
            return True
        return False

    async def register_nym(
        self,
        did: str,
        verkey: str,
        alias: Optional[str] = None,
        role: Optional[str] = None,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
    ) -> Tuple[bool, dict]:
        """Register a nym on the ledger.

        Args:
            did: DID to register on the ledger.
            verkey: The verification key of the keypair.
            alias: Human-friendly alias to assign to the DID.
            role: For permissioned ledgers, what role should the new DID have.
            write_ledger: Whether to write the nym to the ledger.
            endorser_did: DID of the endorser to use for the transaction.
        """
        if self.read_only:
            raise LedgerError(
                "Error cannot register nym when ledger is in read only mode"
            )

        public_info = await self.get_wallet_public_did()
        if not public_info:
            raise BadLedgerRequestError("Cannot register NYM without a public DID")

        try:
            nym_req = ledger.build_nym_request(public_info.did, did, verkey, alias, role)
        except VdrError as err:
            raise LedgerError("Exception when building nym request") from err

        if endorser_did and not write_ledger:
            nym_req.set_endorser(endorser_did)

        resp = await self._submit(
            nym_req, sign=True, sign_did=public_info, write_ledger=write_ledger
        )
        if not write_ledger:
            return True, {"signed_txn": resp}
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            try:
                did_info = await wallet.get_local_did(did)
            except WalletNotFoundError:
                pass  # not a local DID
            else:
                metadata = {**did_info.metadata, **DIDPosture.POSTED.metadata}
                await wallet.replace_local_did_metadata(did, metadata)
        return True, None

    async def get_nym_role(self, did: str) -> Role:
        """Return the role of the input public DID's NYM on the ledger.

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

    async def build_and_return_get_nym_request(
        self, submitter_did: Optional[str], target_did: str
    ) -> str:
        """Build GET_NYM request and return request_json."""
        try:
            request_json = ledger.build_get_nym_request(submitter_did, target_did)
            return request_json
        except VdrError as err:
            raise LedgerError("Exception when building get-nym request") from err

    async def submit_get_nym_request(self, request_json: str) -> str:
        """Submit GET_NYM request to ledger and return response_json."""
        response_json = await self._submit(request_json)
        return response_json

    async def rotate_public_did_keypair(self, next_seed: Optional[str] = None) -> None:
        """Rotate keypair for public DID: create new key, submit to ledger, update wallet.

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

        # fetch current nym info from ledger
        nym = self.did_to_nym(public_did)
        try:
            get_nym_req = ledger.build_get_nym_request(public_did, nym)
        except VdrError as err:
            raise LedgerError("Exception when building nym request") from err

        response = await self._submit(get_nym_req)
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
        # submit the updated nym record
        await self.register_nym(public_did, verkey, alias=alias, role=role_token)

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
            taa_found["digest"] = self.taa_digest(taa_found["version"], taa_found["text"])

        return {
            "aml_record": aml_found,
            "taa_record": taa_found,
            "taa_required": taa_required,
        }

    def taa_rough_timestamp(self) -> int:
        """Get a timestamp accurate to the day.

        Anything more accurate is a privacy concern.
        """
        return int(
            datetime.combine(date.today(), datetime.min.time(), timezone.utc).timestamp()
        )

    async def accept_txn_author_agreement(
        self, taa_record: dict, mechanism: str, accept_time: Optional[int] = None
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
            cache = self.profile.inject_or(BaseCache)
            await storage.add_record(record)
        if cache:
            cache_key = TAA_ACCEPTED_RECORD_TYPE + "::" + self.profile.name
            await cache.set(cache_key, acceptance, self.pool.cache_duration)

    async def get_latest_txn_author_acceptance(self) -> dict:
        """Look up the latest TAA acceptance."""
        cache_key = TAA_ACCEPTED_RECORD_TYPE + "::" + self.profile.name
        acceptance = self.pool.cache and await self.pool.cache.get(cache_key)
        if not acceptance:
            tag_filter = {"pool_name": self.pool_name}
            async with self.profile.session() as session:
                storage = session.inject(BaseStorage)
                cache = self.profile.inject_or(BaseCache)
                found = await storage.find_all_records(
                    TAA_ACCEPTED_RECORD_TYPE, tag_filter
                )
            if found:
                records = [json.loads(record.value) for record in found]
                records.sort(key=lambda v: v["time"], reverse=True)
                acceptance = records[0]
            else:
                acceptance = {}
            if cache:
                await cache.set(cache_key, acceptance, self.pool.cache_duration)
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

        revoc_reg_def = response["data"]
        revoc_reg_def["ver"] = "1.0"
        revoc_reg_def["txnTime"] = response["txnTime"]

        if revoc_reg_def.get("id") != revoc_reg_id:
            raise LedgerError(
                "ID of revocation registry response does not match requested ID"
            )
        return revoc_reg_def

    async def get_revoc_reg_entry(
        self, revoc_reg_id: str, timestamp: int
    ) -> Tuple[dict, int]:
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

        ledger_timestamp = response["data"]["txnTime"]
        reg_entry = {
            "ver": "1.0",
            "value": response["data"]["value"],
        }
        if response["data"]["revocRegDefId"] != revoc_reg_id:
            raise LedgerError(
                "ID of revocation registry response does not match requested ID"
            )
        return reg_entry, ledger_timestamp

    async def get_revoc_reg_delta(
        self, revoc_reg_id: str, timestamp_from=0, timestamp_to=None
    ) -> Tuple[dict, int]:
        """Look up a revocation registry delta by ID.

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

        response_value = response["data"]["value"]
        accum_to = response_value.get("accum_to")

        # If accum_to is not present, then the timestamp_to was before the registry
        # was created. In this case, we need to fetch the registry creation timestamp and
        # re-calculate the delta.
        if not accum_to:
            try:
                (_, timestamp) = await self.get_revoc_reg_entry(revoc_reg_id, int(time()))
                fetch_req = ledger.build_get_revoc_reg_delta_request(
                    public_info and public_info.did,
                    revoc_reg_id,
                    timestamp_from,
                    timestamp,
                )
                response = await self._submit(fetch_req, sign_did=public_info)
                response_value = response["data"]["value"]
            except VdrError as err:
                raise LedgerError(
                    f"get_revoc_reg_delta failed for revoc_reg_id='{revoc_reg_id}'"
                ) from err

        delta_value = {
            "accum": response_value["accum_to"]["value"]["accum"],
            "issued": response_value.get("issued", []),
            "revoked": response_value.get("revoked", []),
        }
        accum_from = response_value.get("accum_from")
        if accum_from:
            delta_value["prev_accum"] = accum_from["value"]["accum"]
        reg_delta = {"ver": "1.0", "value": delta_value}
        # question - why not response["to"] ?
        delta_timestamp = response_value["accum_to"]["txnTime"]
        if response["data"]["revocRegDefId"] != revoc_reg_id:
            raise LedgerError(
                "ID of revocation registry response does not match requested ID"
            )
        return reg_delta, delta_timestamp

    async def send_revoc_reg_def(
        self,
        revoc_reg_def: dict,
        issuer_did: Optional[str] = None,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
    ) -> dict:
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

        if self.profile.context.settings.get("wallet.type") == "askar-anoncreds":
            from acapy_agent.anoncreds.default.legacy_indy.registry import (
                LegacyIndyRegistry,
            )

            rev_reg_def_req = await self._create_revoc_reg_def_request(
                did_info,
                json.dumps(revoc_reg_def),
                write_ledger=write_ledger,
                endorser_did=endorser_did,
            )

            if endorser_did and not write_ledger:
                rev_reg_def_req.set_endorser(endorser_did)

            legacy_indy_registry = LegacyIndyRegistry()
            try:
                resp = await legacy_indy_registry.txn_submit(
                    self,
                    rev_reg_def_req,
                    sign=True,
                    sign_did=did_info,
                    write_ledger=write_ledger,
                )
            except LedgerError as err:
                raise LedgerError(
                    "Exception when sending revocation registry definition"
                ) from err

            if not write_ledger:
                return revoc_reg_def["id"], {"signed_txn": resp}

            try:
                # parse sequence number out of response
                seq_no = json.loads(resp)["result"]["txnMetadata"]["seqNo"]
                return seq_no
            except KeyError as err:
                raise LedgerError(
                    "Failed to parse sequence number from ledger response"
                ) from err
        else:
            try:
                request = ledger.build_revoc_reg_def_request(
                    did_info.did, json.dumps(revoc_reg_def)
                )
                if endorser_did and not write_ledger:
                    request.set_endorser(endorser_did)
            except VdrError as err:
                raise LedgerError(
                    "Exception when sending revocation registry definition"
                ) from err

            resp = await self._submit(
                request, True, sign_did=did_info, write_ledger=write_ledger
            )
            return {"result": resp}

    async def send_revoc_reg_entry(
        self,
        revoc_reg_id: str,
        revoc_def_type: str,
        revoc_reg_entry: dict,
        issuer_did: Optional[str] = None,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
    ) -> dict:
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

        if self.profile.context.settings.get("wallet.type") == "askar-anoncreds":
            from acapy_agent.anoncreds.default.legacy_indy.registry import (
                LegacyIndyRegistry,
            )

            revoc_reg_entry_req = await self._create_revoc_reg_entry_request(
                did_info,
                revoc_reg_id,
                revoc_def_type,
                json.dumps(revoc_reg_entry),
                write_ledger=write_ledger,
                endorser_did=endorser_did,
            )
            if endorser_did and not write_ledger:
                revoc_reg_entry_req.set_endorser(endorser_did)

            legacy_indy_registry = LegacyIndyRegistry()
            resp = await legacy_indy_registry.txn_submit(
                self,
                revoc_reg_entry_req,
                sign=True,
                sign_did=did_info,
                write_ledger=write_ledger,
            )

            if not write_ledger:
                return revoc_reg_id, {"signed_txn": resp}

            try:
                # parse sequence number out of response
                seq_no = json.loads(resp)["result"]["txnMetadata"]["seqNo"]
                return seq_no
            except KeyError as err:
                raise LedgerError(
                    "Failed to parse sequence number from ledger response"
                ) from err
        else:
            try:
                request = ledger.build_revoc_reg_entry_request(
                    did_info.did,
                    revoc_reg_id,
                    revoc_def_type,
                    json.dumps(revoc_reg_entry),
                )
                if endorser_did and not write_ledger:
                    request.set_endorser(endorser_did)
            except VdrError as err:
                raise LedgerError(
                    "Exception when sending revocation registry entry"
                ) from err
            resp = await self._submit(
                request, True, sign_did=did_info, write_ledger=write_ledger
            )
            return {"result": resp}

    async def get_wallet_public_did(self) -> DIDInfo:
        """Fetch the public DID from the wallet."""
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            return await wallet.get_public_did()

    async def txn_endorse(
        self,
        request_json: str,
        endorse_did: Optional[DIDInfo] = None,
    ) -> str:
        """Endorse (sign) the provided transaction."""
        try:
            request = ledger.build_custom_request(request_json)
        except VdrError as err:
            raise BadLedgerRequestError("Cannot endorse invalid request") from err

        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            sign_did = endorse_did if endorse_did else await wallet.get_public_did()
            if not sign_did:
                raise BadLedgerRequestError(
                    "Cannot endorse transaction without a public DID"
                )
            request.set_multi_signature(
                sign_did.did,
                await wallet.sign_message(request.signature_input, sign_did.verkey),
            )
            del wallet

        return request.body

    async def txn_submit(
        self,
        request_json: str,
        sign: bool,
        taa_accept: Optional[bool] = None,
        sign_did: DIDInfo = sentinel,
        write_ledger: bool = True,
    ) -> str:
        """Write the provided (signed and possibly endorsed) transaction to the ledger."""
        resp = await self._submit(
            request_json,
            sign=sign,
            taa_accept=taa_accept,
            sign_did=sign_did,
            write_ledger=write_ledger,
        )
        if write_ledger:
            # match the format returned by indy sdk
            resp = {"op": "REPLY", "result": resp}
        return json.dumps(resp)
