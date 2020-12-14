"""Aries-Askar implementation of BaseStorage interface."""

from typing import Mapping, Sequence

from aries_askar import Session, StoreError, StoreErrorCode

from ..askar.profile import AskarProfile, AskarProfileSession

from .base import (
    DEFAULT_PAGE_SIZE,
    BaseStorage,
    BaseStorageSearch,
    BaseStorageSearchSession,
    validate_record,
)
from .error import (
    StorageError,
    StorageDuplicateError,
    StorageNotFoundError,
    StorageSearchError,
)
from .record import StorageRecord


class AskarStorage(BaseStorage):
    """Aries-Askar Non-Secrets interface."""

    def __init__(self, session: AskarProfileSession):
        """
        Initialize an `AskarStorage` instance.

        Args:
            session: The Askar profile session to use
        """
        self._session = session

    @property
    def session(self) -> Session:
        """Accessor for Askar profile session instance."""
        return self._session

    async def add_record(self, record: StorageRecord):
        """
        Add a new record to the store.

        Args:
            record: `StorageRecord` to be stored

        """
        validate_record(record)
        try:
            await self._session.handle.insert(
                record.type, record.id, record.value, record.tags
            )
        except StoreError as err:
            if err.code == StoreErrorCode.DUPLICATE:
                raise StorageDuplicateError(
                    f"Duplicate record: {record.type}/{record.id}"
                ) from None
            raise StorageError("Error when adding storage record") from err

    async def get_record(
        self, record_type: str, record_id: str, options: Mapping = None
    ) -> StorageRecord:
        """
        Fetch a record from the store by type and ID.

        Args:
            record_type: The record type
            record_id: The record id
            options: A dictionary of backend-specific options

        Returns:
            A `StorageRecord` instance

        Raises:
            StorageError: If the record is not provided
            StorageError: If the record ID not provided
            StorageNotFoundError: If the record is not found
            StorageError: If record not found

        """
        if not record_type:
            raise StorageError("Record type not provided")
        if not record_id:
            raise StorageError("Record ID not provided")
        if not options:
            options = {}
        try:
            if not self._session.handle:
                print(self._session, self._session.handle)
                import traceback

                traceback.print_stack()
                raise SystemExit
            item = await self._session.handle.fetch(record_type, record_id)
        except StoreError as err:
            raise StorageError("Error when fetching storage record") from err
        if not item:
            raise StorageNotFoundError(f"Record not found: {record_type}/{record_id}")
        return StorageRecord(
            type=item.category,
            id=item.name,
            value=None if item.value is None else item.value.decode("utf-8"),
            tags=item.tags or {},
        )

    async def update_record(self, record: StorageRecord, value: str, tags: Mapping):
        """
        Update an existing stored record's value.

        Args:
            record: `StorageRecord` to update
            value: The new value
            tags: The new tags

        Raises:
            StorageNotFoundError: If record not found
            StorageError: If a libindy error occurs

        """
        validate_record(record)
        try:
            await self._session.handle.replace(record.type, record.id, value, tags)
        except StoreError as err:
            if err.code == StoreErrorCode.NOT_FOUND:
                raise StorageNotFoundError("Record not found") from None
            raise StorageError("Error when updating storage record value") from err

    async def delete_record(self, record: StorageRecord):
        """
        Delete a record.

        Args:
            record: `StorageRecord` to delete

        Raises:
            StorageNotFoundError: If record not found
            StorageError: If a libindy error occurs

        """
        validate_record(record, delete=True)
        try:
            await self._session.handle.remove(record.type, record.id)
        except StoreError as err:
            if err.code == StoreErrorCode.NOT_FOUND:
                raise StorageNotFoundError(
                    f"Record not found: {record.type}/{record.id}"
                ) from None
            else:
                raise StorageError("Error when removing storage record") from err

    async def find_record(
        self, type_filter: str, tag_query: Mapping, options: Mapping = None
    ) -> StorageRecord:
        """
        Find a record using a unique tag filter.

        Args:
            type_filter: Filter string
            tag_query: Tags to query
            options: Dictionary of backend-specific options
        """
        try:
            results = await self._session.handle.fetch_all(
                type_filter, tag_query, limit=2
            )
        except StoreError as err:
            raise StorageError("Error when finding storage record") from err
        if len(results) > 1:
            raise StorageDuplicateError("Duplicate records found")
        if not results:
            raise StorageNotFoundError("Record not found")
        row = results[0]
        return StorageRecord(
            type=row.category,
            id=row.name,
            value=None if row.value is None else row.value.decode("utf-8"),
            tags=row.tags,
        )

    async def find_all_records(
        self,
        type_filter: str,
        tag_query: Mapping = None,
        options: Mapping = None,
    ):
        """Retrieve all records matching a particular type filter and tag query."""
        results = []
        for row in await self._session.handle.fetch_all(type_filter, tag_query):
            results.append(
                StorageRecord(
                    type=row.category,
                    id=row.name,
                    value=None if row.value is None else row.value.decode("utf-8"),
                    tags=row.tags,
                )
            )
        return results

    async def delete_all_records(
        self,
        type_filter: str,
        tag_query: Mapping = None,
    ):
        """Remove all records matching a particular type filter and tag query."""
        await self._session.handle.remove_all(type_filter, tag_query)


class AskarStorageSearch(BaseStorageSearch):
    def __init__(self, profile: AskarProfile):
        """
        Initialize an `AskarStorageSearch` instance.

        Args:
            profile: The Askar profile instance to use
        """
        self._profile = profile

    def search_records(
        self,
        type_filter: str,
        tag_query: Mapping = None,
        page_size: int = None,
        options: Mapping = None,
    ) -> "AskarStorageSearchSession":
        """
        Search stored records.

        Args:
            type_filter: Filter string
            tag_query: Tags to query
            page_size: Page size
            options: Dictionary of backend-specific options

        Returns:
            An instance of `AskarStorageSearchSession`

        """
        return AskarStorageSearchSession(
            self._profile, type_filter, tag_query, page_size, options
        )


class AskarStorageSearchSession(BaseStorageSearchSession):
    """Represent an active stored records search."""

    def __init__(
        self,
        profile: AskarProfile,
        type_filter: str,
        tag_query: Mapping,
        page_size: int = None,
        options: Mapping = None,
    ):
        """
        Initialize a `AskarStorageSearchSession` instance.

        Args:
            profile: Askar profile instance to search
            type_filter: Filter string
            tag_query: Tags to search
            page_size: Size of page to return

        """
        self.tag_query = tag_query
        self.type_filter = type_filter
        self.page_size = page_size or DEFAULT_PAGE_SIZE
        self._done = False
        self._scan = None
        self._profile = profile

    @property
    def opened(self) -> bool:
        """
        Accessor for open state.

        Returns:
            True if opened, else False

        """
        return self._scan is not None

    @property
    def handle(self):
        """
        Accessor for search handle.

        Returns:
            The handle

        """
        return self._scan

    def __aiter__(self):
        """Async iterator magic method."""
        return self

    async def __anext__(self):
        """Async iterator magic method."""
        if self._done:
            raise StorageSearchError("Search query is complete")
        await self._open()

        try:
            row = await self._scan.__anext__()
        except StoreError as err:
            raise StorageSearchError("Error when fetching search results") from err
        except StopAsyncIteration:
            self._done = True
            self._scan = None
            raise
        return StorageRecord(
            type=row.category,
            id=row.name,
            value=None if row.value is None else row.value.decode("utf-8"),
            tags=row.tags,
        )

    async def fetch(self, max_count: int = None) -> Sequence[StorageRecord]:
        """
        Fetch the next list of results from the store.

        Args:
            max_count: Max number of records to return

        Returns:
            A list of `StorageRecord` instances

        Raises:
            StorageSearchError: If the search query has not been opened

        """
        if self._done:
            raise StorageSearchError("Search query is complete")
        await self._open()

        count = 0
        ret = []
        limit = max_count or self.page_size

        while count < limit:
            try:
                row = await self._scan.__anext__()
            except StoreError as err:
                raise StorageSearchError("Error when fetching search results") from err
            except StopAsyncIteration:
                break

            ret.append(
                StorageRecord(
                    type=row.category,
                    id=row.name,
                    value=None if row.value is None else row.value.decode("utf-8"),
                    tags=row.tags,
                )
            )
            count += 1

        if not ret:
            self._done = True
            self._scan = None

        return ret

    async def _open(self):
        """Start the search query."""
        if self._scan:
            return
        try:
            self._scan = self._profile.store.scan(self.type_filter, self.tag_query)
        except StoreError as err:
            raise StorageSearchError("Error opening search query") from err

    async def close(self):
        """Dispose of the search query."""
        self._done = True
        self._scan = None
