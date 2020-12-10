import json
import logging
import urllib

from aries_askar import Store, StoreError, StoreErrorCode

from ..core.error import ProfileError, ProfileDuplicateError, ProfileNotFoundError
from ..core.profile import Profile

LOGGER = logging.getLogger(__name__)


class AskarStoreConfig:
    """A helper class for handling Askar store configuration."""

    DEFAULT_KEY = ""
    DEFAULT_KEY_DERIVATION = "kdf:argon2i:mod"
    DEFAULT_STORAGE_TYPE = None

    KEY_DERIVATION_RAW = "RAW"
    KEY_DERIVATION_ARGON2I_INT = "kdf:argon2i:int"
    KEY_DERIVATION_ARGON2I_MOD = "kdf:argon2i:mod"

    def __init__(self, config: dict = None):
        """
        Initialize a `AskarWallet` instance.

        Args:
            config: {name, key, seed, did, auto_recreate, auto_remove,
                     storage_type, storage_config, storage_creds}

        """
        if not config:
            config = {}
        self.auto_recreate = config.get("auto_recreate", False)
        self.auto_remove = config.get("auto_remove", False)
        self.key = config.get("key", self.DEFAULT_KEY)
        self.key_derivation_method = (
            config.get("key_derivation_method") or self.DEFAULT_KEY_DERIVATION
        )
        # self.rekey = config.get("rekey")
        # self.rekey_derivation_method = config.get("rekey_derivation_method")

        self.name = config.get("name") or Profile.DEFAULT_NAME
        self.in_memory = self.name == ":memory:"
        if self.in_memory:
            self.name = Profile.DEFAULT_NAME

        self.storage_config = config.get("storage_config", None)
        self.storage_creds = config.get("storage_creds", None)

        storage_type = config.get("storage_type")
        if storage_type == "default":
            storage_type = "sqlite"
        elif storage_type == "postgres_storage":
            storage_type = "postgres"
        if storage_type not in ("postgres", "sqlite"):
            raise ProfileError(f"Unsupported storage type: {storage_type}")
        if storage_type != "sqlite" and self.in_memory:
            raise ProfileError("In-memory wallet only supported for SQLite backend")
        self.storage_type = storage_type

    @property
    def uri(self) -> str:
        """Accessor for the storage URI."""
        uri = f"{self.storage_type}://"
        if self.storage_type == "sqlite":
            if self.in_memory:
                uri += ":memory:"
            else:
                uri += urllib.parse.quote(f"{self.name}.db")
        elif self.storage_type == "postgres":
            if not self.storage_config:
                raise ProfileError("No 'storage_config' provided for postgres store")
            if not self.storage_creds:
                raise ProfileError("No 'storage_creds' provided for postgres store")
            config = json.loads(self.storage_config)
            creds = json.loads(self.storage_creds)
            config_url = config.get("url")
            if not config_url:
                raise ProfileError("No 'url' provided for postgres store")
            if "account" not in creds:
                raise ProfileError("No 'account' provided for postgres store")
            if "password" not in creds:
                raise ProfileError("No 'password' provided for postgres store")
            account = urllib.parse.quote(creds["account"])
            password = urllib.parse.quote(creds["password"])
            db_name = urllib.parse.quote(self.name)
            # FIXME parse the URL, check for parameters, remove postgres:// prefix, etc
            # config url expected to be in the form "host:port"
            uri += f"{account}:{password}@{config_url}/{db_name}"
            params = {}
            if "connection_timeout" in config:
                params["connect_timeout"] = config["connection_timeout"]
            if "max_connections" in config:
                params["max_connections"] = config["max_connections"]
            if "min_idle_count" in config:
                params["min_connections"] = config["min_idle_count"]
            # FIXME handle 'tls' config parameter
            if "admin_account" in creds:
                params["admin_account"] = creds["admin_account"]
            if "admin_password" in creds:
                params["admin_password"] = creds["admin_password"]
            if params:
                uri += "?" + urllib.parse.urlencode(params)
        return uri

    async def remove_store(self):
        """
        Remove an existing store.

        Raises:
            ProfileNotFoundError: If the wallet could not be found
            ProfileError: If there was another aries_askar error

        """
        try:
            await Store.remove(self.uri)
        except StoreError as err:
            if err.code == StoreErrorCode.NOT_FOUND:
                raise ProfileNotFoundError(
                    f"Store '{self.name}' not found",
                )
            raise ProfileError("Error removing store") from err

    async def open_store(self, provision: bool = False) -> "AskarOpenStore":
        """
        Open a store, removing and/or creating it if so configured.

        Raises:
            ProfileNotFoundError: If the store is not found
            ProfileError: If there is another aries_askar error

        """

        try:
            if provision:
                store = await Store.provision(
                    self.uri,
                    self.key_derivation_method,
                    self.key,
                    recreate=self.auto_recreate,
                )
            else:
                store = await Store.open(
                    self.uri,
                    self.key_derivation_method,
                    self.key,
                )
        except StoreError as err:
            if err.code == StoreErrorCode.DUPLICATE:
                raise ProfileDuplicateError(
                    f"Duplicate store '{self.name}'",
                )
            if err.code == StoreErrorCode.NOT_FOUND:
                raise ProfileNotFoundError(
                    f"Store '{self.name}' not found",
                )
            raise ProfileError("Error opening store") from err

        return AskarOpenStore(self, provision, store)


class AskarOpenStore:
    """Handle and metadata for an opened Askar store."""

    def __init__(
        self,
        config: AskarStoreConfig,
        created,
        store: Store,
    ):
        """Create a new AskarOpenStore instance."""
        self.config = config
        self.created = created
        self.store = store

    @property
    def name(self) -> str:
        return self.config.name

    async def close(self):
        """Close previously-opened store, removing it if so configured."""
        if self.store:
            await self.store.close(remove=self.config.auto_remove)
            self.store = None
