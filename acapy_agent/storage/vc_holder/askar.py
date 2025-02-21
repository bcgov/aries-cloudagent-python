"""Askar storage implementation of VC holder interface."""

import json
from typing import Mapping, Optional, Sequence

from ...askar.profile import AskarProfile
from ..askar import AskarStorage, AskarStorageSearch, AskarStorageSearchSession
from ..record import StorageRecord
from .base import VCHolder, VCRecordSearch
from .vc_record import VCRecord
from .xform import VC_CRED_RECORD_TYPE


class AskarVCHolder(VCHolder):
    """Askar VC record storage class."""

    def __init__(self, profile: AskarProfile):
        """Initialize the Indy-SDK VC holder instance."""
        self._profile = profile

    def build_type_or_schema_query(self, uri_list: Sequence[str]) -> dict:
        """Build and return indy-specific type_or_schema_query."""
        type_or_schema_query = {}
        for uri in uri_list:
            q = {"$or": [{"type": uri}, {"schema": uri}]}
            if type_or_schema_query:
                if "$and" not in type_or_schema_query:
                    type_or_schema_query = {"$and": [type_or_schema_query]}
                type_or_schema_query["$and"].append(q)
            else:
                type_or_schema_query = q
        return type_or_schema_query

    async def store_credential(self, cred: VCRecord):
        """Add a new VC record to the store.

        Args:
            cred: The VCRecord instance to store
        Raises:
            StorageDuplicateError: If the record_id is not unique

        """
        record = vc_to_storage_record(cred)
        async with self._profile.session() as session:
            await AskarStorage(session).add_record(record)

    async def retrieve_credential_by_id(self, record_id: str) -> VCRecord:
        """Fetch a VC record by its record ID.

        Raises:
            StorageNotFoundError: If the record is not found

        """
        async with self._profile.session() as session:
            record = await AskarStorage(session).get_record(
                VC_CRED_RECORD_TYPE, record_id
            )
        return storage_to_vc_record(record)

    async def retrieve_credential_by_given_id(self, given_id: str) -> VCRecord:
        """Fetch a VC record by its given ID ('id' property).

        Raises:
            StorageNotFoundError: If the record is not found

        """
        async with self._profile.session() as session:
            record = await AskarStorage(session).find_record(
                VC_CRED_RECORD_TYPE, {"given_id": given_id}
            )
        return storage_to_vc_record(record)

    async def delete_credential(self, cred: VCRecord):
        """Remove a previously-stored VC record.

        Raises:
            StorageNotFoundError: If the record is not found

        """
        async with self._profile.session() as session:
            await AskarStorage(session).delete_record(vc_to_storage_record(cred))

    def search_credentials(
        self,
        contexts: Sequence[str] = None,
        types: Sequence[str] = None,
        schema_ids: Sequence[str] = None,
        issuer_id: Optional[str] = None,
        subject_ids: Optional[str] = None,
        proof_types: Sequence[str] = None,
        given_id: Optional[str] = None,
        tag_query: Optional[Mapping] = None,
        pd_uri_list: Sequence[str] = None,
    ) -> "VCRecordSearch":
        """Start a new VC record search.

        Args:
            contexts: An inclusive list of JSON-LD contexts to match
            types: An inclusive list of JSON-LD types to match
            schema_ids: An inclusive list of credential schema identifiers
            issuer_id: The ID of the credential issuer
            subject_ids: The IDs of credential subjects all of which to match
            proof_types: The signature suite types used for the proof objects.
            given_id: The given id of the credential
            tag_query: A tag filter clause
            pd_uri_list: A list of presentation definition URIs to match

        """

        def _match_any(query: list, k, vals):
            if vals is None:
                pass
            elif len(vals) > 1:
                query.append({"$or": [{k: v for v in vals}]})
            else:
                query.append({k: vals[0]})

        def _make_custom_query(query):
            result = {}
            for k, v in query.items():
                if isinstance(v, (list, set)) and k != "$exist":
                    result[k] = [_make_custom_query(cl) for cl in v]
                elif k.startswith("$"):
                    result[k] = v
                else:
                    result[f"cstm:{k}"] = v
            return result

        query = []
        _match_any(query, "context", contexts)
        _match_any(query, "type", types)
        _match_any(query, "schema", schema_ids)
        _match_any(query, "subject", subject_ids)
        _match_any(query, "proof_type", proof_types)
        if issuer_id:
            query.append({"issuer_id": issuer_id})
        if given_id:
            query.append({"given_id": given_id})
        if tag_query:
            query.append(_make_custom_query(tag_query))
        if pd_uri_list:
            query.append(self.build_type_or_schema_query(pd_uri_list))
        query = {"$and": query} if query else None
        search = AskarStorageSearch(self._profile).search_records(
            VC_CRED_RECORD_TYPE, query
        )
        return AskarVCRecordSearch(search)


class AskarVCRecordSearch(VCRecordSearch):
    """Askar storage search for VC records."""

    def __init__(self, search: AskarStorageSearchSession):
        """Initialize the Askar VC record search."""
        self._search = search

    async def close(self):
        """Dispose of the search query."""
        await self._search.close()

    async def fetch(self, max_count: Optional[int] = None) -> Sequence[VCRecord]:
        """Fetch the next list of VC records from the store.

        Args:
            max_count: Max number of records to return. If not provided,
              defaults to the backend's preferred page size

        Returns:
            A list of `VCRecord` instances

        """
        rows = await self._search.fetch(max_count)
        records = [storage_to_vc_record(r) for r in rows]
        return records


def storage_to_vc_record(record: StorageRecord) -> VCRecord:
    """Convert an Askar stored record into a VC record."""

    def _make_set(val) -> set:
        if isinstance(val, str):
            return {val}
        else:
            return set(val)

    cred_tags = {}
    contexts = set()
    types = set()
    schema_ids = set()
    subject_ids = set()
    proof_types = set()
    issuer_id = None
    given_id = None
    for tagname, tagval in (record.tags or {}).items():
        if tagname == "context":
            contexts = _make_set(tagval)
        elif tagname == "type":
            types = _make_set(tagval)
        elif tagname == "schema":
            schema_ids = _make_set(tagval)
        elif tagname == "subject":
            subject_ids = _make_set(tagval)
        elif tagname == "proof_type":
            proof_types = _make_set(tagval)
        elif tagname == "issuer_id":
            issuer_id = tagval
        elif tagname == "given_id":
            given_id = tagval
        elif tagname.startswith("cstm:"):
            cred_tags[tagname[5:]] = tagval
    return VCRecord(
        contexts=contexts,
        expanded_types=types,
        schema_ids=schema_ids,
        issuer_id=issuer_id,
        subject_ids=subject_ids,
        proof_types=proof_types,
        cred_value=json.loads(record.value),
        given_id=given_id,
        cred_tags=cred_tags,
        record_id=record.id,
    )


def vc_to_storage_record(cred: VCRecord) -> StorageRecord:
    """Convert a VC record into an Askar stored record."""
    tags = {}
    tags["context"] = set(cred.contexts)
    tags["type"] = set(cred.expanded_types)
    tags["schema"] = set(cred.schema_ids)
    tags["subject"] = set(cred.subject_ids)
    tags["proof_type"] = set(cred.proof_types)
    if cred.issuer_id:
        tags["issuer_id"] = cred.issuer_id
    if cred.given_id:
        tags["given_id"] = cred.given_id
    for tagname, tagval in (cred.cred_tags or {}).items():
        tags[f"cstm:{tagname}"] = tagval

    return StorageRecord(
        VC_CRED_RECORD_TYPE,
        json.dumps(cred.cred_value),
        tags,
        cred.record_id,
    )
