from ..ld_proofs.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
    DID_V1_CONTEXT_URL,
    SECURITY_CONTEXT_BBS_URL,
    SECURITY_CONTEXT_ED25519_2020_URL,
    SECURITY_CONTEXT_V1_URL,
    SECURITY_CONTEXT_V2_URL,
    SECURITY_CONTEXT_V3_URL,
    SECURITY_CONTEXT_MULTIKEY_URL,
)
from .contexts import (
    BBS_V1,
    CITIZENSHIP_V1,
    CREDENTIALS_V1,
    CREDENTIALS_V2,
    DID_V1,
    DIF_PRESENTATION_SUBMISSION_V1,
    ED25519_2020_V1,
    MULTIKEY_V1,
    EXAMPLES_V1,
    ODRL,
    SCHEMA_ORG,
    SECURITY_V1,
    SECURITY_V2,
    SECURITY_V3_UNSTABLE,
    VACCINATION_V1,
)
from .dids import (
    DID_EXAMPLE_48939859,
    DID_SOV_QqEfJxe752NCmWqR5TssZ5,
    DID_z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL,
    DID_zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq,
    DID_zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa,
)

DOCUMENTS = {
    DID_z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL.get(
        "id"
    ): DID_z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL,
    DID_zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq.get(
        "id"
    ): DID_zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq,
    DID_zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa.get(
        "id"
    ): DID_zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa,
    DID_EXAMPLE_48939859.get("id"): DID_EXAMPLE_48939859,
    DID_SOV_QqEfJxe752NCmWqR5TssZ5.get("id"): DID_SOV_QqEfJxe752NCmWqR5TssZ5,
    SECURITY_CONTEXT_V1_URL: SECURITY_V1,
    SECURITY_CONTEXT_V2_URL: SECURITY_V2,
    SECURITY_CONTEXT_V3_URL: SECURITY_V3_UNSTABLE,
    DID_V1_CONTEXT_URL: DID_V1,
    CREDENTIALS_CONTEXT_V1_URL: CREDENTIALS_V1,
    CREDENTIALS_CONTEXT_V2_URL: CREDENTIALS_V2,
    SECURITY_CONTEXT_BBS_URL: BBS_V1,
    SECURITY_CONTEXT_ED25519_2020_URL: ED25519_2020_V1,
    SECURITY_CONTEXT_MULTIKEY_URL: MULTIKEY_V1,
    "https://www.w3.org/2018/credentials/examples/v1": EXAMPLES_V1,
    "https://w3id.org/citizenship/v1": CITIZENSHIP_V1,
    "https://www.w3.org/ns/odrl.jsonld": ODRL,
    "http://schema.org/": SCHEMA_ORG,
    "https://w3id.org/vaccination/v1": VACCINATION_V1,
    "https://identity.foundation/presentation-exchange/submission/v1": DIF_PRESENTATION_SUBMISSION_V1,
}


def custom_document_loader(url: str, options: dict):
    # Check if full url (with fragments is in document map)
    if url in DOCUMENTS:
        return {
            "contentType": "application/ld+json",
            "contextUrl": None,
            "document": DOCUMENTS[url],
            "documentUrl": url,
        }

    # Otherwise look if it is present without fragment
    without_fragment = url.split("#")[0]
    if without_fragment in DOCUMENTS:
        return {
            "contentType": "application/ld+json",
            "contextUrl": None,
            "document": DOCUMENTS[without_fragment],
            "documentUrl": url,
        }

    raise Exception(f"No custom context support for {url}")
