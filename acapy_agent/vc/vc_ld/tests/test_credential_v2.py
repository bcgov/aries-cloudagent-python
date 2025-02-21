from ...ld_proofs import DocumentVerificationResult, ProofResult, PurposeResult

CREDENTIAL_V2_TEMPLATE = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    "type": ["VerifiableCredential"],
    "issuer": {"id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"},
    "credentialSubject": {
        "id": "did:example:alice",
        "name": "Alice",
    },
}

CREDENTIAL_V2_ISSUED = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    "type": ["VerifiableCredential"],
    "issuer": {"id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"},
    "credentialSubject": {"id": "did:example:alice", "name": "Alice"},
    "proof": {
        "type": "Ed25519Signature2020",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
        "created": "2025-01-27T21:39:18+00:00",
        "proofValue": "zK9VFcysBRqQHQL65WNmKKPbYYrhFabu41SuQXMBGVEHHYLNGrELkNxg2GAxEs6phDZoGNcvhTBhv7fLmJ23U8Hn",
    },
}

CREDENTIAL_V2_VERIFIED = DocumentVerificationResult(
    verified=True,
    document={
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "type": ["VerifiableCredential"],
        "issuer": {"id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"},
        "credentialSubject": {"id": "did:example:alice", "name": "Alice"},
        "proof": {
            "type": "Ed25519Signature2020",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
            "created": "2025-01-27T21:39:18+00:00",
            "proofValue": "zK9VFcysBRqQHQL65WNmKKPbYYrhFabu41SuQXMBGVEHHYLNGrELkNxg2GAxEs6phDZoGNcvhTBhv7fLmJ23U8Hn",
        },
    },
    results=[
        ProofResult(
            verified=True,
            proof={
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://w3id.org/security/suites/ed25519-2020/v1",
                ],
                "type": "Ed25519Signature2020",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2025-01-27T21:39:18+00:00",
                "proofValue": "zK9VFcysBRqQHQL65WNmKKPbYYrhFabu41SuQXMBGVEHHYLNGrELkNxg2GAxEs6phDZoGNcvhTBhv7fLmJ23U8Hn",
            },
            purpose_result=PurposeResult(
                valid=True,
                controller={
                    "@context": "https://w3id.org/security/v2",
                    "id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                    "assertionMethod": [
                        "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                    ],
                    "authentication": [
                        {
                            "id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                            "type": "Ed25519VerificationKey2018",
                            "controller": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                            "publicKeyBase58": "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx",
                        }
                    ],
                    "capabilityDelegation": [
                        "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                    ],
                    "capabilityInvocation": [
                        "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                    ],
                    "keyAgreement": [
                        {
                            "id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6LSbkodSr6SU2trs8VUgnrnWtSm7BAPG245ggrBmSrxbv1R",
                            "type": "X25519KeyAgreementKey2019",
                            "controller": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                            "publicKeyBase58": "5dTvYHaNaB7mk7iA9LqCJEHG2dGZQsvoi8WGzDRtYEf",
                        }
                    ],
                    "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                },
            ),
        )
    ],
)

PRESENTATION_V2_UNSIGNED = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiablePresentation"],
    "holder": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
    "verifiableCredential": [
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "type": ["VerifiableCredential"],
            "issuer": {"id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"},
            "credentialSubject": {"id": "did:example:alice", "name": "Alice"},
            "proof": {
                "type": "Ed25519Signature2020",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2025-01-27T21:39:18+00:00",
                "proofValue": "zK9VFcysBRqQHQL65WNmKKPbYYrhFabu41SuQXMBGVEHHYLNGrELkNxg2GAxEs6phDZoGNcvhTBhv7fLmJ23U8Hn",
            },
        }
    ],
}

PRESENTATION_V2_SIGNED = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    "type": ["VerifiablePresentation"],
    "holder": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
    "verifiableCredential": [
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "type": ["VerifiableCredential"],
            "issuer": {"id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"},
            "credentialSubject": {"id": "did:example:alice", "name": "Alice"},
            "proof": {
                "type": "Ed25519Signature2020",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "created": "2025-01-27T21:39:18+00:00",
                "proofValue": "zK9VFcysBRqQHQL65WNmKKPbYYrhFabu41SuQXMBGVEHHYLNGrELkNxg2GAxEs6phDZoGNcvhTBhv7fLmJ23U8Hn",
            },
        }
    ],
    "proof": {
        "type": "Ed25519Signature2020",
        "proofPurpose": "authentication",
        "verificationMethod": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
        "created": "2025-01-27T21:50:39+00:00",
        "challenge": "2b1bbff6-e608-4368-bf84-67471b27e41c",
        "proofValue": "z61aNLNSyBVZyYY5xEKYnGDzWbXQhpWa8QXmQMMJpy4zZ71kyxGbRHVwMWdEzU4qwQhLZ7eSfQiX4dENquYGxkbcB",
    },
}
