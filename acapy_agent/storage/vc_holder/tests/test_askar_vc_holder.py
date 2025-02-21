import pytest

from ....storage.error import StorageDuplicateError, StorageNotFoundError
from ....utils.testing import create_test_profile
from ..base import VCHolder
from ..vc_record import VCRecord

VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
VC_TYPE = "https://www.w3.org/2018/credentials#VerifiableCredential"
VC_SUBJECT_ID = "did:example:ebfeb1f712ebc6f1c276e12ec21"
VC_PROOF_TYPE = "Ed25519Signature2018"
VC_ISSUER_ID = "https://example.edu/issuers/14"
VC_SCHEMA_ID = "https://example.org/examples/degree.json"
VC_GIVEN_ID = "http://example.edu/credentials/3732"


@pytest.fixture()
async def holder():
    profile = await create_test_profile(settings={"wallet.type": "askar"})
    yield profile.inject(VCHolder)


@pytest.fixture
def record():
    yield VCRecord(
        contexts=[
            VC_CONTEXT,
            "https://www.w3.org/2018/credentials/examples/v1",
        ],
        expanded_types=[
            VC_TYPE,
            "https://example.org/examples#UniversityDegreeCredential",
        ],
        schema_ids=[VC_SCHEMA_ID],
        issuer_id=VC_ISSUER_ID,
        subject_ids=[VC_SUBJECT_ID],
        proof_types=[VC_PROOF_TYPE],
        given_id=VC_GIVEN_ID,
        cred_tags={"tag": "value"},
        cred_value={
            "@context": [
                VC_CONTEXT,
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "id": VC_GIVEN_ID,
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": VC_ISSUER_ID,
            "identifier": "83627467",
            "name": "University Degree",
            "issuanceDate": "2010-01-01T19:53:24Z",
            "credentialSubject": {
                "id": VC_SUBJECT_ID,
                "givenName": "Cai",
                "familyName": "Leblanc",
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2021-05-07T08:50:17.626625",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..rubQvgig7cN-F6cYn_AJF1BCSaMpkoR517Ot_4pqwdJnQ-JwKXq6d6cNos5JR73E9WkwYISXapY0fYTIG9-fBA",
            },
        },
    )


@pytest.mark.asyncio
async def test_tag_query(holder: VCHolder, record: VCRecord):
    test_uri_list = [
        "https://www.w3.org/2018/credentials#VerifiableCredential",
        "https://example.org/examples#UniversityDegreeCredential",
    ]
    test_query = holder.build_type_or_schema_query(test_uri_list)
    assert test_query == {
        "$and": [
            {
                "$or": [
                    {"type": "https://www.w3.org/2018/credentials#VerifiableCredential"},
                    {
                        "schema": "https://www.w3.org/2018/credentials#VerifiableCredential"
                    },
                ]
            },
            {
                "$or": [
                    {"type": "https://example.org/examples#UniversityDegreeCredential"},
                    {"schema": "https://example.org/examples#UniversityDegreeCredential"},
                ]
            },
        ]
    }
    await holder.store_credential(record)

    search = holder.search_credentials(pd_uri_list=test_uri_list)
    rows = await search.fetch()
    assert rows == [record]

    @pytest.mark.asyncio
    async def test_handle_parser_error(holder: VCHolder):
        record = VCRecord(
            contexts=[
                VC_CONTEXT,
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            expanded_types=[
                VC_TYPE,
                "https://example.org/examples#UniversityDegreeCredential",
            ],
            schema_ids=[VC_SCHEMA_ID],
            issuer_id=VC_ISSUER_ID,
            subject_ids=[VC_SUBJECT_ID],
            proof_types=[VC_PROOF_TYPE],
            given_id=VC_GIVEN_ID,
            cred_tags={"tag": "value"},
            cred_value={
                "@context": [
                    VC_CONTEXT,
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
                "id": VC_GIVEN_ID,
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "issuer": VC_ISSUER_ID,
                "identifier": "83627467",
                "name": "University Degree",
                "issuanceDate": "20180-10-29T21:02:19.201+0000",
                "credentialSubject": {
                    "id": VC_SUBJECT_ID,
                    "givenName": "Cai",
                    "familyName": "Leblanc",
                },
                "proof": {
                    "type": "Ed25519Signature2018",
                    "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                    "created": "2021-05-07T08:50:17.626625",
                    "proofPurpose": "assertionMethod",
                    "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..rubQvgig7cN-F6cYn_AJF1BCSaMpkoR517Ot_4pqwdJnQ-JwKXq6d6cNos5JR73E9WkwYISXapY0fYTIG9-fBA",
                },
            },
        )
        await holder.store_credential(record)
        search = holder.search_credentials()
        rows = await search.fetch()
        assert rows == [record]


@pytest.mark.asyncio
async def test_sorting_vcrecord(holder: VCHolder):
    record_a = VCRecord(
        contexts=[
            VC_CONTEXT,
            "https://www.w3.org/2018/credentials/examples/v1",
        ],
        expanded_types=[
            VC_TYPE,
            "https://example.org/examples#UniversityDegreeCredential",
        ],
        schema_ids=[VC_SCHEMA_ID],
        issuer_id=VC_ISSUER_ID,
        subject_ids=[VC_SUBJECT_ID],
        proof_types=[VC_PROOF_TYPE],
        given_id=VC_GIVEN_ID,
        cred_tags={"tag": "value"},
        cred_value={
            "@context": [
                VC_CONTEXT,
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "id": VC_GIVEN_ID,
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": VC_ISSUER_ID,
            "identifier": "83627467",
            "name": "University Degree",
            "issuanceDate": "2010-01-01T19:53:24Z",
            "credentialSubject": {
                "id": VC_SUBJECT_ID,
                "givenName": "Cai",
                "familyName": "Leblanc",
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2021-05-07T08:50:17.626625",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..rubQvgig7cN-F6cYn_AJF1BCSaMpkoR517Ot_4pqwdJnQ-JwKXq6d6cNos5JR73E9WkwYISXapY0fYTIG9-fBA",
            },
        },
    )
    await holder.store_credential(record_a)
    record_b = VCRecord(
        contexts=[
            VC_CONTEXT,
            "https://www.w3.org/2018/credentials/examples/v1",
        ],
        expanded_types=[
            VC_TYPE,
            "https://example.org/examples#UniversityDegreeCredential",
        ],
        schema_ids=[VC_SCHEMA_ID],
        issuer_id=VC_ISSUER_ID,
        subject_ids=[VC_SUBJECT_ID],
        proof_types=[VC_PROOF_TYPE],
        given_id=VC_GIVEN_ID,
        cred_tags={"tag": "value"},
        cred_value={
            "@context": [
                VC_CONTEXT,
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "id": VC_GIVEN_ID,
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": VC_ISSUER_ID,
            "identifier": "83627467",
            "name": "University Degree",
            "issuanceDate": "2012-01-01T19:53:24Z",
            "credentialSubject": {
                "id": VC_SUBJECT_ID,
                "givenName": "Cai",
                "familyName": "Leblanc",
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2021-05-07T08:50:17.626625",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..rubQvgig7cN-F6cYn_AJF1BCSaMpkoR517Ot_4pqwdJnQ-JwKXq6d6cNos5JR73E9WkwYISXapY0fYTIG9-fBA",
            },
        },
    )
    await holder.store_credential(record_b)
    record_c = VCRecord(
        contexts=[
            VC_CONTEXT,
            "https://www.w3.org/2018/credentials/examples/v1",
        ],
        expanded_types=[
            VC_TYPE,
            "https://example.org/examples#UniversityDegreeCredential",
        ],
        schema_ids=[VC_SCHEMA_ID],
        issuer_id=VC_ISSUER_ID,
        subject_ids=[VC_SUBJECT_ID],
        proof_types=[VC_PROOF_TYPE],
        given_id=VC_GIVEN_ID,
        cred_tags={"tag": "value"},
        cred_value={
            "@context": [
                VC_CONTEXT,
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "id": VC_GIVEN_ID,
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": VC_ISSUER_ID,
            "identifier": "83627467",
            "name": "University Degree",
            "issuanceDate": "2009-01-01T19:53:24Z",
            "credentialSubject": {
                "id": VC_SUBJECT_ID,
                "givenName": "Cai",
                "familyName": "Leblanc",
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2021-05-07T08:50:17.626625",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..rubQvgig7cN-F6cYn_AJF1BCSaMpkoR517Ot_4pqwdJnQ-JwKXq6d6cNos5JR73E9WkwYISXapY0fYTIG9-fBA",
            },
        },
    )
    await holder.store_credential(record_c)
    # expected = [record_b, record_a, record_c]

    search = holder.search_credentials()
    rows = await search.fetch()
    assert rows  # == expected


@pytest.mark.asyncio
async def test_tag_query_valid_and_operator(holder: VCHolder, record: VCRecord):
    test_uri_list = [
        "https://www.w3.org/2018/credentials#VerifiableCredential",
        "https://example.org/examples#UniversityDegreeCredential2",
    ]
    await holder.store_credential(record)

    search = holder.search_credentials(pd_uri_list=test_uri_list)
    rows = await search.fetch()
    assert rows == []


@pytest.mark.asyncio
async def test_store_retrieve(holder: VCHolder, record: VCRecord):
    await holder.store_credential(record)
    result = await holder.retrieve_credential_by_id(record.record_id)
    assert result == record

    result = await holder.retrieve_credential_by_given_id(record.given_id)
    assert result == record

    with pytest.raises(StorageDuplicateError):
        await holder.store_credential(record)

    with pytest.raises(StorageNotFoundError):
        await holder.retrieve_credential_by_id("missing")

    with pytest.raises(StorageNotFoundError):
        await holder.retrieve_credential_by_given_id("missing")


@pytest.mark.asyncio
async def test_delete(holder: VCHolder, record: VCRecord):
    await holder.store_credential(record)
    await holder.delete_credential(record)
    with pytest.raises(StorageNotFoundError):
        await holder.retrieve_credential_by_id(record.record_id)


@pytest.mark.asyncio
async def test_search(holder: VCHolder, record: VCRecord):
    await holder.store_credential(record)

    search = holder.search_credentials()
    rows = await search.fetch()
    assert rows == [record]
    await search.close()

    # test async iter and repr
    search = holder.search_credentials()
    assert search.__class__.__name__ in str(search)
    rows = []
    async for row in search:
        rows.append(row)
    assert rows == [record]
    await search.close()

    search = holder.search_credentials(
        contexts=[VC_CONTEXT],
        types=[VC_TYPE],
        schema_ids=[VC_SCHEMA_ID],
        subject_ids=[VC_SUBJECT_ID],
        proof_types=[VC_PROOF_TYPE],
        issuer_id=VC_ISSUER_ID,
        given_id=VC_GIVEN_ID,
        tag_query={"tag": "value"},
    )
    rows = await search.fetch()
    assert rows == [record]

    rows = await holder.search_credentials(contexts=["other-context"]).fetch()
    assert not rows

    rows = await holder.search_credentials(types=["other-type"]).fetch()
    assert not rows

    rows = await holder.search_credentials(schema_ids=["other schema"]).fetch()
    assert not rows

    rows = await holder.search_credentials(subject_ids=["other subject"]).fetch()
    assert not rows

    rows = await holder.search_credentials(proof_types=["other proof type"]).fetch()
    assert not rows

    rows = await holder.search_credentials(issuer_id="other issuer").fetch()
    assert not rows

    rows = await holder.search_credentials(given_id="other given id").fetch()
    assert not rows

    await search.close()
