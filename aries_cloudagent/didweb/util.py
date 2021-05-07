from pydid import DIDDocument
from enum import Enum
from ..core.profile import ProfileSession
from ..storage.base import (
    BaseStorage,
    StorageRecord,
    StorageNotFoundError,
)

RECORD_TYPE_DID_DOC = "did_doc"


class VerificationMethod(Enum):

    BLS12381G2 = "Bls12381G2Key2020"
    ED25519 = "Ed25519VerificationKey2018"


async def retrieve_did_document(
    session: ProfileSession
) -> DIDDocument:
    """Retrieve DID document."""
    storage = session.inject(BaseStorage)
    try:
        record = await storage.find_record(
            RECORD_TYPE_DID_DOC,
            {"did": "did:web"}
        )
    except StorageNotFoundError:
        record = None
    return DIDDocument.from_json(record.value) if record else None


async def save_did_document(
    did_document: DIDDocument, session: ProfileSession
):
    """Save a DID document"""
    storage = session.inject(BaseStorage)
    try:
        record = await storage.find_record(
            RECORD_TYPE_DID_DOC,
            {"did": "did:web"}
        )
    except StorageNotFoundError:
        if did_document:
            record = StorageRecord(
                type=RECORD_TYPE_DID_DOC,
                value=did_document.to_json(),
                tags={"did": "did:web"}
            )
            await storage.add_record(record)
    else:
        if did_document:
            await storage.update_record(
                record, did_document.to_json(), {"did": "did:web"}
            )
        else:
            await storage.delete_record(record)
