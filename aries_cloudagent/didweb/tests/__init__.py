DOC = {
    "@context": "https://w3id.org/did/v1",
    "id": "did:example:1234abcd",
    "verificationMethod": [
        {
            "id": "did:example:1234abcd#4",
            "type": "RsaVerificationKey2018",
            "controller": "did:example:1234abcd",
            "publicKeyPem": "-----BEGIN PUBLIC X…",
        },
        {
            "id": "did:example:1234abcd#5",
            "type": "RsaVerificationKey2018",
            "controller": "did:example:1234abcd",
            "publicKeyPem": "-----BEGIN PUBLIC 9…",
        },
        {
            "id": "did:example:1234abcd#6",
            "type": "RsaVerificationKey2018",
            "controller": "did:example:1234abcd",
            "publicKeyPem": "-----BEGIN PUBLIC A…",
        },
    ],
    "authentication": [
        {
            "id": "did:example:123456789abcdefghi#ted",
            "controller": "did:example:1234abcd",
            "type": "RsaSignatureAuthentication2018",
            "publicKey": "did:example:1234abcd#4",
        },
        "did:example:123456789abcdefghi#5",
    ],
    "service": [
        {
            "id": "did:example:123456789abcdefghi#did-communication",
            "type": "did-communication",
            "priority": 0,
            "recipientKeys": ["did:example:1234abcd#4"],
            "routingKeys": ["did:example:1234abcd#6"],
            "serviceEndpoint": "did:example:xd45fr567794lrzti67;did-communication",
        }
    ],
}
