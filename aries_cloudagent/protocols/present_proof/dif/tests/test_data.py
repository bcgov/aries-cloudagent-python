import datetime
import pytest
import json

from .....storage.vc_holder.vc_record import VCRecord
from .....resolver.did_resolver_registry import DIDResolverRegistry
from .....resolver.did_resolver import DIDResolver

from ..pres_exch import PresentationDefinition
from ..pres_exch_handler import DIFPresExchError

from .....core.in_memory import InMemoryProfile
from .....did.did_key import DIDKey
from .....vc.vc_ld.issue import issue
from .....vc.ld_proofs.document_loader import DocumentLoader
from .....vc.tests.document_loader import custom_document_loader
from .....vc.ld_proofs import (
    BbsBlsSignatureProof2020,
    BbsBlsSignature2020,
    Ed25519Signature2018,
    WalletKeyPair,
)
from .....wallet.base import BaseWallet
from .....wallet.crypto import KeyType
from .....wallet.util import b58_to_bytes
from .....wallet.in_memory import InMemoryWallet

def create_vc_record(cred_dict: dict):
    given_id = cred_dict.get("id")
    contexts = [ctx for ctx in cred_dict.get("@context") if type(ctx) is str]

    # issuer
    issuer = cred_dict.get("issuer")
    if type(issuer) is dict:
        issuer = issuer.get("id")

    # types
    types = [_type for _type in cred_dict.get("type")]

    # subjects
    subjects = cred_dict.get("credentialSubject")
    if type(subjects) is dict:
        subjects = [subjects]
    subject_ids = [subject.get("id") for subject in subjects if subject.get("id")]

    # Schemas
    schemas = cred_dict.get("credentialsSchema", [])
    if type(schemas) is dict:
        schemas = [schemas]
    schema_ids = [schema.get("id") for schema in schemas]

    # Proofs (this can be done easier if we use the expanded version)
    proofs = cred_dict.get("proof") or []
    proof_types = None
    if type(proofs) is dict:
        proofs = [proofs]
    if proofs:
        proof_types = [proof.get("type") for proof in proofs]

    return VCRecord(
        contexts=contexts,
        types=types,
        issuer_id=issuer,
        subject_ids=subject_ids,
        proof_types=proof_types,
        given_id=given_id,
        cred_value=cred_dict,
        schema_ids=schema_ids,
    )
    
bbs_bls_number_filter_creds = [
    create_vc_record(
        {
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"], 
            "id": "https://issuer.oidp.uscis.gov/credentials/83627465", 
            "type": ["VerifiableCredential", "PermanentResidentCard"], 
            "issuer": "did:example:489398593", 
            "identifier": "83627465", 
            "name": "Permanent Resident Card", 
            "description": "Government of Example Permanent Resident Card.", 
            "issuanceDate": "2010-01-01T19:53:24Z", 
            "expirationDate": "2029-12-03T12:19:52Z", 
            "credentialSubject": {
                "id": "did:example:b34ca6cd37bbf23",
                "type": ["PermanentResident", "Person"], 
                "givenName": "JOHN", 
                "familyName": "SMITH", 
                "gender": "Male", 
                "image": "data:image/png;base64,iVBORw0KGgokJggg==",
                "residentSince": "2015-01-01", 
                "lprCategory": "C09", 
                "lprNumber": "999-999-999", 
                "commuterClassification": "C1", 
                "birthCountry": "Bahamas", 
                "birthDate": "1958-07-17",
                "test": 2
            }, 
            "proof": {
                "type": "BbsBlsSignature2020", 
                "verificationMethod": "did:example:489398593#test", 
                "created": "2021-04-13T23:23:56.045014", 
                "proofPurpose": "assertionMethod", 
                "proofValue": "rhD+4HOhPfLywBuhLYMi1i0kWa/L2Qipt+sqTRiebjoo4OF3ESoGnm+L4Movz128Mjns60H0Bz7W+aqN1dPP9uhU/FGBKW/LEIGJX1rrrYgn17CkWp46z/hwQy+8c9ulOCn0Yq3BDqB37euoBTZbOQ=="
            }
        }
    ),
    create_vc_record(
        {
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"], 
            "id": "https://issuer.oidp.uscis.gov/credentials/83627466", 
            "type": ["VerifiableCredential", "PermanentResidentCard"], 
            "issuer": "did:example:489398593", 
            "identifier": "83627466", 
            "name": "Permanent Resident Card", 
            "description": "Government of Example Permanent Resident Card.", 
            "issuanceDate": "2010-01-01T19:53:24Z", 
            "expirationDate": "2029-12-03T12:19:52Z", 
            "credentialSubject": {
                "id": "did:example:b34ca6cd37bbf23",
                "type": ["PermanentResident", "Person"],
                "givenName": "Theodor",
                "familyName": "Major",
                "gender": "Male",
                "image": "data:image/png;base64,iVBORw0KGgokJggg==",
                "residentSince": "2017-01-01",
                "lprCategory": "C09",
                "lprNumber": "999-999-999",
                "commuterClassification": "C1",
                "birthCountry": "Canada",
                "birthDate": "1968-07-17",
                "test": 2
            }, 
            "proof": {
                "type": "BbsBlsSignature2020",
                "verificationMethod": "did:example:489398593#test",
                "created": "2021-04-13T23:33:05.798834",
                "proofPurpose": "assertionMethod",
                "proofValue": "jp8ahSYYFhRAk+1ahfG8qu7iEjQnEXp3P3fWgTrc4khxmw9/9mGACq67YW9r917/aKYTQcVyojelN3cBHrjBvaOzb7bZ6Ps0Wf6WFq1gc0QFUrdiN0mJRl5YAz8R16sLxrPsoS/8ji1MoabjqmlnWQ=="
            }
        }
    ),
    create_vc_record(
        {
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"],
            "id": "https://issuer.oidp.uscis.gov/credentials/83627467",
            "type": ["VerifiableCredential", "PermanentResidentCard"], 
            "issuer": "did:example:489398593", 
            "identifier": "83627467", 
            "name": "Permanent Resident Card", 
            "description": "Government of Example Permanent Resident Card.", 
            "issuanceDate": "2010-01-01T19:53:24Z",
            "expirationDate": "2029-12-03T12:19:52Z", 
            "credentialSubject": {
                "id": "did:example:b34ca6cd37bbf33", 
                "type": ["PermanentResident", "Person"], 
                "givenName": "Cai", 
                "familyName": "Leblanc", 
                "gender": "Male", 
                "image": "data:image/png;base64,iVBORw0KGgokJggg==",
                "residentSince": "2015-01-01", 
                "lprCategory": "C09",
                "lprNumber": "999-999-9989",
                "commuterClassification": "C1",
                "birthCountry": "Canada", 
                "birthDate": "1975-07-17",
                "test": 3
            }, 
            "proof": {
                "type": "BbsBlsSignature2020",
                "verificationMethod": "did:example:489398593#test",
                "created": "2021-04-13T23:40:44.835154", 
                "proofPurpose":"assertionMethod",
                "proofValue": "t8+TPbYqF/dGlEn+qNnEFL1L0QeUjgXlYfJ7AelzOhb7cr2CjP/MIcG5bAQ5l6F2OZKNyE8RsPY14xedrkxpyv1oyWPmXzOwr0gt6ElLJm9jAUwFoZ7xAYHSedcR3Lh4FFuqmxfBHYF3A6VgSlMSfA=="
            }
        }
    ),
]

edd_jsonld_creds = [
    create_vc_record(
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/citizenship/v1",
            ],
            "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": "did:example:489398593",
            "identifier": "83627465",
            "name": "Permanent Resident Card",
            "description": "Government of Example Permanent Resident Card.",
            "issuanceDate": "2010-01-01T19:53:24Z",
            "expirationDate": "2029-12-03T12:19:52Z",
            "credentialSubject": {
                "id": "did:example:b34ca6cd37bbf23",
                "type": ["PermanentResident", "Person"],
                "givenName": "JOHN",
                "familyName": "SMITH",
                "gender": "Male",
                "image": "data:image/png;base64,iVBORw0KGgokJggg==",
                "residentSince": "2015-01-01",
                "lprCategory": "C09",
                "lprNumber": "999-999-999",
                "commuterClassification": "C1",
                "birthCountry": "Bahamas",
                "birthDate": "1958-07-17",
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2021-04-14T23:12:56.395319",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..z274d6OdDbyzokrlkiWNgfFSPA1kOR9E38Gt3TueveeVa1kSaDEkGhPsnXEyof3ZjhCANHhyfRlHytZjvhGcAA",
            },
        }
    ),
    create_vc_record(
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/citizenship/v1",
            ],
            "id": "https://issuer.oidp.uscis.gov/credentials/83627466",
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": "did:example:489398593",
            "identifier": "83627466",
            "name": "Permanent Resident Card",
            "description": "Government of Example Permanent Resident Card.",
            "issuanceDate": "2010-01-01T19:53:24Z",
            "expirationDate": "2029-12-03T12:19:52Z",
            "credentialSubject": {
                "id": "did:example:b34ca6cd37bbf23",
                "type": ["PermanentResident", "Person"],
                "givenName": "Theodor",
                "familyName": "Major",
                "gender": "Male",
                "image": "data:image/png;base64,iVBORw0KGgokJggg==",
                "residentSince": "2017-01-01",
                "lprCategory": "C09",
                "lprNumber": "999-999-999",
                "commuterClassification": "C1",
                "birthCountry": "Canada",
                "birthDate": "1968-07-17",
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2021-04-14T23:25:50.902717",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..Zm9PlsFS-M_Y35AFNEeY_79NwgsCEUmtt8dBScePqYU-6K4AA_8TcmYAiOaxTY5jzIN8iWuH7HgHugMh612yDg",
            },
        }
    ),
    create_vc_record(
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/citizenship/v1",
            ],
            "id": "https://issuer.oidp.uscis.gov/credentials/83627467",
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": "did:example:489398593",
            "identifier": "83627467",
            "name": "Permanent Resident Card",
            "description": "Government of Example Permanent Resident Card.",
            "issuanceDate": "2010-01-01T19:53:24Z",
            "expirationDate": "2029-12-03T12:19:52Z",
            "credentialSubject": {
                "id": "did:example:b34ca6cd37bbf33",
                "type": ["PermanentResident", "Person"],
                "givenName": "Cai",
                "familyName": "Leblanc",
                "gender": "Male",
                "image": "data:image/png;base64,iVBORw0KGgokJggg==",
                "residentSince": "2015-01-01",
                "lprCategory": "C09",
                "lprNumber": "999-999-9989",
                "commuterClassification": "C1",
                "birthCountry": "Canada",
                "birthDate": "1975-07-17",
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2021-04-14T23:32:44.938165",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..jp9oGHEfZJw2MiK0M_3PAJX3U1OLrFEreWvUXRX6Vym911mrjILtl6Im59hijUXWqyKH-dh1McmUrFSGwzudAw",
            },
        }
    ),
]

cred_1 = {
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"], 
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465", 
  "type": ["VerifiableCredential", "PermanentResidentCard"], 
  "issuer": "did:example:489398593", 
  "identifier": "83627465", 
  "name": "Permanent Resident Card", 
  "description": "Government of Example Permanent Resident Card.", 
  "issuanceDate": "2010-01-01T19:53:24Z", 
  "expirationDate": "2029-12-03T12:19:52Z", 
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23",
    "type": ["PermanentResident", "Person"], 
    "givenName": "JOHN", 
    "familyName": "SMITH", 
    "gender": "Male", 
    "image": "data:image/png;base64,iVBORw0KGgokJggg==",
    "residentSince": "2015-01-01", 
    "lprCategory": "C09", 
    "lprNumber": "999-999-999", 
    "commuterClassification": "C1", 
    "birthCountry": "Bahamas", 
    "birthDate": "1958-07-17"
  }, 
  "proof": {
    "type": "BbsBlsSignature2020", 
    "verificationMethod": "did:example:489398593#test", 
    "created": "2021-04-13T23:23:56.045014", 
    "proofPurpose": "assertionMethod", 
    "proofValue": "rhD+4HOhPfLywBuhLYMi1i0kWa/L2Qipt+sqTRiebjoo4OF3ESoGnm+L4Movz128Mjns60H0Bz7W+aqN1dPP9uhU/FGBKW/LEIGJX1rrrYgn17CkWp46z/hwQy+8c9ulOCn0Yq3BDqB37euoBTZbOQ=="
  }
}

cred_2 = {
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"], 
  "id": "https://issuer.oidp.uscis.gov/credentials/83627466", 
  "type": ["VerifiableCredential", "PermanentResidentCard"], 
  "issuer": "did:example:489398593", 
  "identifier": "83627466", 
  "name": "Permanent Resident Card", 
  "description": "Government of Example Permanent Resident Card.", 
  "issuanceDate": "2010-01-01T19:53:24Z", 
  "expirationDate": "2029-12-03T12:19:52Z", 
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23",
    "type": ["PermanentResident", "Person"],
    "givenName": "Theodor",
    "familyName": "Major",
    "gender": "Male",
    "image": "data:image/png;base64,iVBORw0KGgokJggg==",
    "residentSince": "2017-01-01",
    "lprCategory": "C09",
    "lprNumber": "999-999-999",
    "commuterClassification": "C1",
    "birthCountry": "Canada",
    "birthDate": "1968-07-17"
  }, 
  "proof": {
    "type": "BbsBlsSignature2020",
    "verificationMethod": "did:example:489398593#test",
    "created": "2021-04-13T23:33:05.798834",
    "proofPurpose": "assertionMethod",
    "proofValue": "jp8ahSYYFhRAk+1ahfG8qu7iEjQnEXp3P3fWgTrc4khxmw9/9mGACq67YW9r917/aKYTQcVyojelN3cBHrjBvaOzb7bZ6Ps0Wf6WFq1gc0QFUrdiN0mJRl5YAz8R16sLxrPsoS/8ji1MoabjqmlnWQ=="
  }
}

cred_3 = {
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627467",
  "type": ["VerifiableCredential", "PermanentResidentCard"], 
  "issuer": "did:example:489398593", 
  "identifier": "83627467", 
  "name": "Permanent Resident Card", 
  "description": "Government of Example Permanent Resident Card.", 
  "issuanceDate": "2010-01-01T19:53:24Z",
  "expirationDate": "2029-12-03T12:19:52Z", 
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf33", 
    "type": ["PermanentResident", "Person"], 
    "givenName": "Cai", 
    "familyName": "Leblanc", 
    "gender": "Male", 
    "image": "data:image/png;base64,iVBORw0KGgokJggg==",
    "residentSince": "2015-01-01", 
    "lprCategory": "C09",
    "lprNumber": "999-999-9989",
    "commuterClassification": "C1",
    "birthCountry": "Canada", 
    "birthDate": "1975-07-17"
  }, 
  "proof": {
    "type": "BbsBlsSignature2020",
    "verificationMethod": "did:example:489398593#test",
    "created": "2021-04-13T23:40:44.835154", 
    "proofPurpose":"assertionMethod",
    "proofValue": "t8+TPbYqF/dGlEn+qNnEFL1L0QeUjgXlYfJ7AelzOhb7cr2CjP/MIcG5bAQ5l6F2OZKNyE8RsPY14xedrkxpyv1oyWPmXzOwr0gt6ElLJm9jAUwFoZ7xAYHSedcR3Lh4FFuqmxfBHYF3A6VgSlMSfA=="
  }
}

cred_4 = {
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627468",
  "type": ["VerifiableCredential", "PermanentResidentCard"], 
  "issuer": "did:example:489398593", 
  "identifier": "83627468", 
  "name": "Permanent Resident Card", 
  "description": "Government of Example Permanent Resident Card.", 
  "issuanceDate": "2010-01-01T19:53:24Z",
  "expirationDate": "2029-12-03T12:19:52Z", 
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf43", 
    "type": ["PermanentResident", "Person"], 
    "givenName": "Jamel", 
    "familyName": "Huber",
    "gender": "Female", 
    "image": "data:image/png;base64,iVBORw0KGgokJggg==",
    "residentSince": "2012-01-01", 
    "lprCategory": "C09", 
    "lprNumber": "999-999-000",
    "commuterClassification": "C1", 
    "birthCountry": "United States",
    "birthDate": "1959-07-17"
  }, 
  "proof": {
    "type": "BbsBlsSignature2020",
    "verificationMethod": "did:example:489398593#test",
    "created": "2021-04-13T23:50:55.908652",
    "proofPurpose": "assertionMethod",
    "proofValue": "hN5JopRqXyCZNczB2tg/jRXoOel3QIGoYaJkEhzR5TrvABGXiavt4XxmwzPh/CNNKEH2yU34/q4yOz0m5blqgdrWeMoez+c2fu1oWThoSQRbxv+QSu1CQPAV2hn0KoLv1gpUpgRnDdpYfKyhPsk70Q=="
    }
}

cred_5 = {
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627469",
  "type": ["VerifiableCredential", "PermanentResidentCard"], 
  "issuer": "did:example:489398593", 
  "identifier": "83627469", 
  "name": "Permanent Resident Card", 
  "description": "Government of Example Permanent Resident Card.", 
  "issuanceDate": "2010-01-01T19:53:24Z", 
  "expirationDate": "2029-12-03T12:19:52Z", 
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23",
    "type": ["PermanentResident", "Person"],
    "givenName": "Vivek",
    "familyName": "Easton",
    "gender": "Male",
    "image": "data:image/png;base64,iVBORw0KGgokJggg==",
    "residentSince": "2019-01-01",
    "lprCategory": "C09",
    "lprNumber": "999-999-888",
    "commuterClassification": "C1",
    "birthCountry": "India",
    "birthDate": "1990-07-17"
  }, 
  "proof": {
    "type": "BbsBlsSignature2020",
    "verificationMethod": "did:example:489398593#test",
    "created": "2021-04-14T00:10:42.070455",
    "proofPurpose": "assertionMethod",
    "proofValue": "mNoC0IJ8r/LCpsQy0zfVvFSxJ2aGMsMEPsKhiew0pCbXicvloIGnkgtZz75kUrEENpr1bxEmm/VDaVywZjDULnpSmwAf+KKQcGPqsod6UjgyW5wutMM2K8/ug3kEh+16n0LPbqIeTiq7QzFzV+iwgA=="
  }
}

cred_6 = {
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"], 
  "id": "https://issuer.oidp.uscis.gov/credentials/83627470",
  "type": ["VerifiableCredential", "PermanentResidentCard"], 
  "issuer": "did:example:489398593", 
  "identifier": "83627470", 
  "name": "Permanent Resident Card", 
  "description": "Government of Example Permanent Resident Card.", 
  "issuanceDate": "2010-01-01T19:53:24Z", 
  "expirationDate": "2029-12-03T12:19:52Z", 
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23", 
    "type": ["PermanentResident", "Person"], 
    "givenName": "Ralphie", 
    "familyName": "Jennings", 
    "gender": "Female", 
    "image": "data:image/png;base64,iVBORw0KGgokJggg==", 
    "residentSince": "2010-01-01", 
    "lprCategory": "C09", 
    "lprNumber": "999-999-777", 
    "commuterClassification": "C1", 
    "birthCountry": "Canada", 
    "birthDate": "1980-07-17"
  }, 
  "proof": {
    "type": "BbsBlsSignature2020",
    "verificationMethod": "did:example:489398593#test",
    "created": "2021-04-14T00:20:16.276326",
    "proofPurpose": "assertionMethod", 
    "proofValue": "oBbXUmZD9HqGXi2ODpQIHE0KHp7IUkvn2+HVHEmwP0BQAsaUIlTsoSgNPpzYiYYtHCbqUusVvCquIVaUA6MQVuf1SeGLw94z5u2P+m5BAw1PEXYaJxQDHxw+egjQ5eRxAxS9AzOFwg/luBrkSjEoiw=="
  }
}

pres_exch_nested_srs_a = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "Citizenship Information",
      "rule": "pick",
      "count": 1,
      "from_nested": [
        {
          "name": "United States Citizenship Proofs",
          "purpose": "We need you to prove you are a US citizen.",
          "rule": "all",
          "from": "A"
        },
        {
          "name": "European Union Citizenship Proofs",
          "purpose": "We need you to prove you are a citizen of a EU country.",
          "rule": "all",
          "from": "B"
        }
      ]
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer.id",
              "$.issuer",
              "$.vc.issuer.id"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "enum": ["did:example:489398593"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "maximum":"2009-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_nested_srs_b = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "Citizenship Information",
      "rule": "pick",
      "count": 1,
      "from_nested": [
        {
          "name": "United States Citizenship Proofs",
          "purpose": "We need you to prove you are a US citizen.",
          "rule": "all",
          "from": "A"
        },
        {
          "name": "European Union Citizenship Proofs",
          "purpose": "We need you to prove you are a citizen of a EU country.",
          "rule": "all",
          "from": "B"
        }
      ]
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer.id",
              "$.issuer",
              "$.vc.issuer.id"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "enum": ["did:key:test"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "maximum":"2012-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_multiple_srs_not_met = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "Citizenship Information",
      "rule": "pick",
      "count": 2,
      "from": "A"
    },
    {
      "name": "European Union Citizenship Proofs",
      "purpose": "We need you to prove you are a citizen of a EU country.",
      "rule": "all",
      "from": "B"
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer.id",
              "$.vc.issuer.id",
              "$.issuer"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "enum": ["did:example:489398593"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "exclusiveMax":"2009-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_multiple_srs_met = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "Citizenship Information",
      "rule": "all",
      "from": "A"
    },
    {
      "name": "European Union Citizenship Proofs",
      "rule": "all",
      "from": "B"
    },
    {
      "name": "Date Test",
      "rule": "all",
      "from": "C"
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
           "path":[
              "$.issuer.id",
              "$.vc.issuer.id",
              "$.issuer"
            ],
            "filter":{
              "type":"string",
              "enum": ["did:example:489398593"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.credentialSubject.gender"
            ],
            "filter":{
              "const":"Male"
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_3",
      "name":"US Passport",
      "group":[
        "C"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "minimum":"2005-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_datetime_minimum_met = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "European Union Citizenship Proofs",
      "rule": "all",
      "from": "A"
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "minimum":"2005-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_datetime_maximum_met = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "European Union Citizenship Proofs",
      "rule": "all",
      "from": "A"
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "maximum":"2014-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""


def get_test_data():
    creds_json_list = [
        cred_1,
        cred_2,
        cred_3,
        cred_4,
        cred_5,
        cred_6,
    ]

    vc_record_list = []
    for cred in creds_json_list:
        vc_record_list.append(create_vc_record(cred))
    pd_json_list = [
        (pres_exch_multiple_srs_not_met, 0),
        (pres_exch_multiple_srs_met, 4),
        (pres_exch_datetime_minimum_met, 6),
        (pres_exch_datetime_maximum_met, 6),
        (pres_exch_nested_srs_a, 6),
        (pres_exch_nested_srs_b, 6),
    ]

    pd_list = []
    for pd in pd_json_list:
        pd_list.append(
            (
                PresentationDefinition.deserialize(json.loads(pd[0])),
                pd[1],
            )
        )
    # Returns VCRecords, PDsList, profile and suites for PresExch Tests
    return (vc_record_list, pd_list)