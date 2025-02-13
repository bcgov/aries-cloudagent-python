"""Minimal reproducible example script.

This script is for you to use to reproduce a bug or demonstrate a feature.
"""

import asyncio
import json
from dataclasses import dataclass
from os import getenv

from acapy_controller import Controller
from acapy_controller.logging import logging_to_stdout
from acapy_controller.models import V20PresExRecord
from acapy_controller.protocols import (
    DIDResult,
    didexchange,
    indy_anoncred_credential_artifacts,
    indy_anoncreds_publish_revocation,
    indy_anoncreds_revoke,
    indy_issue_credential_v2,
    indy_present_proof_v2,
    params,
)
from aiohttp import ClientSession

ALICE = getenv("ALICE", "http://alice:3001")
BOB = getenv("BOB", "http://bob:3001")


def summary(presentation: V20PresExRecord) -> str:
    """Summarize a presentation exchange record."""
    request = presentation.pres_request
    return "Summary: " + json.dumps(
        {
            "state": presentation.state,
            "verified": presentation.verified,
            "presentation_request": request.dict(by_alias=True) if request else None,
        },
        indent=2,
        sort_keys=True,
    )


@dataclass
class IndyDidCreateResponse:
    """Response from creating a DID."""

    did: str
    verkey: str


async def main():
    """Test Controller protocols."""
    async with Controller(base_url=ALICE) as alice, Controller(base_url=BOB) as bob:
        # Connecting
        alice_conn, bob_conn = await didexchange(alice, bob)

        # Issuance prep
        config = (await alice.get("/status/config"))["config"]
        genesis_url = config.get("ledger.genesis_url")
        public_did = (await alice.get("/wallet/did/public", response=DIDResult)).result
        if not public_did:
            public_did = await alice.post(
                "/did/indy/create",
                json={},
                response=IndyDidCreateResponse,
            )
            assert public_did

            async with ClientSession() as session:
                register_url = genesis_url.replace("/genesis", "/register")
                async with session.post(
                    register_url,
                    json={
                        "did": public_did.did,
                        "verkey": public_did.verkey,
                        "alias": None,
                        "role": "ENDORSER",
                    },
                ) as resp:
                    assert resp.ok

            await alice.post("/wallet/did/public", params=params(did=public_did.did))
        _, cred_def = await indy_anoncred_credential_artifacts(
            alice,
            ["firstname", "lastname"],
            support_revocation=True,
        )

        # Issue a credential
        alice_cred_ex, _ = await indy_issue_credential_v2(
            alice,
            bob,
            alice_conn.connection_id,
            bob_conn.connection_id,
            cred_def.credential_definition_id,
            {"firstname": "Bob", "lastname": "Builder"},
        )

        # Present the the credential's attributes
        await indy_present_proof_v2(
            bob,
            alice,
            bob_conn.connection_id,
            alice_conn.connection_id,
            requested_attributes=[{"name": "firstname"}],
        )

        # Revoke credential
        await indy_anoncreds_revoke(
            alice,
            cred_ex=alice_cred_ex,
            holder_connection_id=alice_conn.connection_id,
            notify=True,
        )
        await indy_anoncreds_publish_revocation(alice, cred_ex=alice_cred_ex)
        await bob.record(topic="revocation-notification")


if __name__ == "__main__":
    logging_to_stdout()
    asyncio.run(main())
