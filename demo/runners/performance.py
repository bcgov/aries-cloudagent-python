import asyncio
import logging
import os
import random
import sys

from typing import Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.support.agent import (  # noqa:E402
    DemoAgent,
    default_genesis_txns,
    start_mediator_agent,
    connect_wallet_to_mediator,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_timer,
    progress,
    require_indy,
)

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
LOGGER = logging.getLogger(__name__)
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))


class BaseAgent(DemoAgent):
    def __init__(
        self,
        ident: str,
        port: int,
        prefix: str = None,
        **kwargs,
    ):
        if prefix is None:
            prefix = ident
        super().__init__(ident, port, port + 1, prefix=prefix, **kwargs)
        self._connection_id = None
        self._connection_ready = None
        self.credential_state = {}
        self.credential_event = asyncio.Event()
        self.revocations = []
        self.ping_state = {}
        self.ping_event = asyncio.Event()
        self.sent_pings = set()

    @property
    def connection_id(self) -> str:
        return self._connection_id

    @connection_id.setter
    def connection_id(self, conn_id: str):
        self._connection_id = conn_id
        self._connection_ready = asyncio.Future()

    async def detect_connection(self):
        if not self._connection_ready:
            raise Exception("No connection to await")
        await self._connection_ready
        self._connection_ready = None

    async def handle_oob_invitation(self, message):
        pass

    async def handle_connections(self, payload):
        conn_id = payload["connection_id"]
        if (not self.connection_id) and (payload["state"] in ("invitation", "request")):
            self.connection_id = conn_id
        if conn_id == self.connection_id:
            if payload["state"] == "active" and not self._connection_ready.done():
                self.log("Connected")
                self._connection_ready.set_result(True)

    async def handle_issue_credential_v2_0(self, payload):
        cred_ex_id = payload["cred_ex_id"]
        self.credential_state[cred_ex_id] = payload["state"]
        self.credential_event.set()

    async def handle_issue_credential_v2_0_indy(self, payload):
        rev_reg_id = payload.get("rev_reg_id")
        cred_rev_id = payload.get("cred_rev_id")
        if rev_reg_id and cred_rev_id:
            self.revocations.append((rev_reg_id, cred_rev_id))

    async def handle_issuer_cred_rev(self, message):
        pass

    async def handle_ping(self, payload):
        thread_id = payload["thread_id"]
        if thread_id in self.sent_pings or (
            payload["state"] == "received"
            and payload["comment"]
            and payload["comment"].startswith("test-ping")
        ):
            self.ping_state[thread_id] = payload["state"]
            self.ping_event.set()

    async def check_received_creds(self) -> Tuple[int, int]:
        while True:
            self.credential_event.clear()
            pending = 0
            total = len(self.credential_state)
            for result in self.credential_state.values():
                if result != "done":
                    pending += 1
            if self.credential_event.is_set():
                continue
            return pending, total

    async def update_creds(self):
        await self.credential_event.wait()

    async def check_received_pings(self) -> Tuple[int, int]:
        while True:
            self.ping_event.clear()
            result = {}
            for thread_id, state in self.ping_state.items():
                if not result.get(state):
                    result[state] = set()
                result[state].add(thread_id)
            if self.ping_event.is_set():
                continue
            return result

    async def update_pings(self):
        await self.ping_event.wait()

    async def send_ping(self, ident: str = None) -> str:
        resp = await self.admin_POST(
            f"/connections/{self.connection_id}/send-ping",
            {"comment": f"test-ping {ident}"},
        )
        self.sent_pings.add(resp["thread_id"])

    def check_task_exception(self, fut: asyncio.Task):
        if fut.done():
            try:
                exc = fut.exception()
            except asyncio.CancelledError as e:
                exc = e
            if exc:
                self.log(f"Task raised exception: {str(exc)}")


class AliceAgent(BaseAgent):
    def __init__(self, port: int, **kwargs):
        super().__init__("Alice", port, seed=None, **kwargs)
        self.extra_args = [
            "--auto-accept-invites",
            "--auto-accept-requests",
            "--auto-respond-credential-offer",
            "--auto-store-credential",
            "--monitor-ping",
        ]
        self.timing_log = "logs/alice_perf.log"

    async def fetch_credential_definition(self, cred_def_id):
        return await self.admin_GET(f"/credential-definitions/{cred_def_id}")

    async def propose_credential(
        self,
        cred_attrs: dict,
        cred_def_id: str,
        comment: str = None,
        auto_remove: bool = True,
    ):
        cred_preview = {
            "attributes": [{"name": n, "value": v} for (n, v) in cred_attrs.items()]
        }
        await self.admin_POST(
            "/issue-credential/send-proposal",
            {
                "connection_id": self.connection_id,
                "cred_def_id": cred_def_id,
                "credential_proposal": cred_preview,
                "comment": comment,
                "auto_remove": auto_remove,
            },
        )


class FaberAgent(BaseAgent):
    def __init__(self, port: int, **kwargs):
        super().__init__("Faber", port, **kwargs)
        self.extra_args = [
            "--auto-accept-invites",
            "--auto-accept-requests",
            "--monitor-ping",
            "--auto-respond-credential-proposal",
            "--auto-respond-credential-request",
        ]
        self.schema_id = None
        self.credential_definition_id = None
        self.revocation_registry_id = None

    async def publish_defs(self, support_revocation: bool = False):
        # create a schema
        self.log("Publishing test schema")
        version = format(
            "%d.%d.%d"
            % (random.randint(1, 101), random.randint(1, 101), random.randint(1, 101))
        )
        schema_body = {
            "schema_name": "degree schema",
            "schema_version": version,
            "attributes": ["name", "date", "degree", "age"],
        }
        schema_response = await self.admin_POST("/schemas", schema_body)
        self.schema_id = schema_response["sent"]["schema_id"]
        self.log(f"Schema ID: {self.schema_id}")

        # create a cred def for the schema
        self.log("Publishing test credential definition")
        credential_definition_body = {
            "schema_id": self.schema_id,
            "support_revocation": support_revocation,
            "revocation_registry_size": TAILS_FILE_COUNT,
        }
        credential_definition_response = await self.admin_POST(
            "/credential-definitions", credential_definition_body
        )
        self.credential_definition_id = credential_definition_response["sent"][
            "credential_definition_id"
        ]
        self.log(f"Credential Definition ID: {self.credential_definition_id}")

    async def send_credential(
        self, cred_attrs: dict, comment: str = None, auto_remove: bool = True
    ):
        cred_preview = {
            "@type": CRED_PREVIEW_TYPE,
            "attributes": [{"name": n, "value": v} for (n, v) in cred_attrs.items()],
        }
        await self.admin_POST(
            "/issue-credential-2.0/send",
            {
                "filter": {"indy": {"cred_def_id": self.credential_definition_id}},
                "auto_remove": auto_remove,
                "comment": comment,
                "connection_id": self.connection_id,
                "credential_preview": cred_preview,
            },
        )

    async def revoke_credential(self, cred_ex_id: str):
        await self.admin_POST(
            "/revocation/revoke",
            {
                "cred_ex_id": cred_ex_id,
                "publish": True,
            },
        )


async def main(
    start_port: int,
    threads: int = 20,
    action: str = None,
    show_timing: bool = False,
    multitenant: bool = False,
    mediation: bool = False,
    use_did_exchange: bool = False,
    revocation: bool = False,
    tails_server_base_url: str = None,
    issue_count: int = 300,
    wallet_type: str = None,
):

    genesis = await default_genesis_txns()
    if not genesis:
        print("Error retrieving ledger genesis transactions")
        sys.exit(1)

    alice = None
    faber = None
    alice_mediator_agent = None
    faber_mediator_agent = None
    run_timer = log_timer("Total runtime:")
    run_timer.start()

    try:
        alice = AliceAgent(
            start_port,
            genesis_data=genesis,
            timing=show_timing,
            multitenant=multitenant,
            mediation=mediation,
            wallet_type=wallet_type,
        )
        await alice.listen_webhooks(start_port + 2)

        faber = FaberAgent(
            start_port + 3,
            genesis_data=genesis,
            timing=show_timing,
            tails_server_base_url=tails_server_base_url,
            multitenant=multitenant,
            mediation=mediation,
            wallet_type=wallet_type,
        )
        await faber.listen_webhooks(start_port + 5)
        await faber.register_did()

        with log_timer("Startup duration:"):
            await alice.start_process()
            await faber.start_process()

            if mediation:
                alice_mediator_agent = await start_mediator_agent(
                    start_port + 8, genesis
                )
                if not alice_mediator_agent:
                    raise Exception("Mediator agent returns None :-(")
                faber_mediator_agent = await start_mediator_agent(
                    start_port + 11, genesis
                )
                if not faber_mediator_agent:
                    raise Exception("Mediator agent returns None :-(")
            else:
                alice_mediator_agent = None
                faber_mediator_agent = None

        with log_timer("Connect duration:"):
            if multitenant:
                # create an initial managed sub-wallet (also mediated)
                await alice.register_or_switch_wallet(
                    "Alice.initial",
                    webhook_port=None,
                    mediator_agent=alice_mediator_agent,
                )
                await faber.register_or_switch_wallet(
                    "Faber.initial",
                    public_did=True,
                    webhook_port=None,
                    mediator_agent=faber_mediator_agent,
                )
            elif mediation:
                # we need to pre-connect the agent(s) to their mediator (use the same
                # mediator for both)
                if not await connect_wallet_to_mediator(alice, alice_mediator_agent):
                    log_msg("Mediation setup FAILED :-(")
                    raise Exception("Mediation setup FAILED :-(")
                if not await connect_wallet_to_mediator(faber, faber_mediator_agent):
                    log_msg("Mediation setup FAILED :-(")
                    raise Exception("Mediation setup FAILED :-(")

            invite = await faber.get_invite(use_did_exchange)
            await alice.receive_invite(invite["invitation"])
            await asyncio.wait_for(faber.detect_connection(), 30)

        if action != "ping":
            with log_timer("Publish duration:"):
                await faber.publish_defs(revocation)
            # cache the credential definition
            await alice.fetch_credential_definition(faber.credential_definition_id)

        if show_timing:
            await alice.reset_timing()
            await faber.reset_timing()
            if mediation:
                await alice_mediator_agent.reset_timing()
                await faber_mediator_agent.reset_timing()

        batch_size = 100

        semaphore = asyncio.Semaphore(threads)

        def done_propose(fut: asyncio.Task):
            semaphore.release()
            alice.check_task_exception(fut)

        def done_send(fut: asyncio.Task):
            semaphore.release()
            faber.check_task_exception(fut)

        def test_cred(index: int) -> dict:
            return {
                "name": "Alice Smith",
                "date": f"{2020+index}-05-28",
                "degree": "Maths",
                "age": "24",
            }

        async def propose_credential(index: int):
            await semaphore.acquire()
            comment = f"propose test credential {index}"
            attributes = test_cred(index)
            asyncio.ensure_future(
                alice.propose_credential(
                    attributes, faber.credential_definition_id, comment, not revocation
                )
            ).add_done_callback(done_propose)

        async def send_credential(index: int):
            await semaphore.acquire()
            comment = f"issue test credential {index}"
            attributes = test_cred(index)
            asyncio.ensure_future(
                faber.send_credential(attributes, comment, not revocation)
            ).add_done_callback(done_send)

        async def check_received_creds(agent, issue_count, pb):
            reported = 0
            iter_pb = iter(pb) if pb else None
            while True:
                pending, total = await agent.check_received_creds()
                complete = total - pending
                if reported == complete:
                    await asyncio.wait_for(agent.update_creds(), 30)
                    continue
                if iter_pb and complete > reported:
                    try:
                        while next(iter_pb) < complete:
                            pass
                    except StopIteration:
                        iter_pb = None
                reported = complete
                if reported == issue_count:
                    break

        async def send_ping(index: int):
            await semaphore.acquire()
            asyncio.ensure_future(faber.send_ping(str(index))).add_done_callback(
                done_send
            )

        async def check_received_pings(agent, issue_count, pb):
            reported = 0
            iter_pb = iter(pb) if pb else None
            while True:
                pings = await agent.check_received_pings()
                complete = sum(len(tids) for tids in pings.values())
                if complete == reported:
                    await asyncio.wait_for(agent.update_pings(), 30)
                    continue
                if iter_pb and complete > reported:
                    try:
                        while next(iter_pb) < complete:
                            pass
                    except StopIteration:
                        iter_pb = None
                reported = complete
                if reported >= issue_count:
                    break

        if action == "ping":
            recv_timer = faber.log_timer(f"Completed {issue_count} ping exchanges in")
            batch_timer = faber.log_timer(f"Started {batch_size} ping exchanges in")
        else:
            recv_timer = faber.log_timer(
                f"Completed {issue_count} credential exchanges in"
            )
            batch_timer = faber.log_timer(
                f"Started {batch_size} credential exchanges in"
            )
        recv_timer.start()
        batch_timer.start()

        with progress() as pb:
            receive_task = None
            try:
                if action == "ping":
                    issue_pg = pb(range(issue_count), label="Sending pings")
                    receive_pg = pb(range(issue_count), label="Responding pings")
                    check_received = check_received_pings
                    send = send_ping
                    completed = f"Done sending {issue_count} pings in"
                else:
                    issue_pg = pb(range(issue_count), label="Issuing credentials")
                    receive_pg = pb(range(issue_count), label="Receiving credentials")
                    check_received = check_received_creds
                    if action == "propose":
                        send = propose_credential
                    else:
                        send = send_credential
                    completed = f"Done starting {issue_count} credential exchanges in"

                issue_task = asyncio.ensure_future(
                    check_received(faber, issue_count, issue_pg)
                )
                issue_task.add_done_callback(faber.check_task_exception)
                receive_task = asyncio.ensure_future(
                    check_received(alice, issue_count, receive_pg)
                )
                receive_task.add_done_callback(alice.check_task_exception)
                with faber.log_timer(completed):
                    for idx in range(0, issue_count):
                        await send(idx + 1)
                        if not (idx + 1) % batch_size and idx < issue_count - 1:
                            batch_timer.reset()

                await issue_task
                await receive_task
            except KeyboardInterrupt:
                if receive_task:
                    receive_task.cancel()
                print("Cancelled")

        recv_timer.stop()
        avg = recv_timer.duration / issue_count
        item_short = "ping" if action == "ping" else "cred"
        item_long = "ping exchange" if action == "ping" else "credential"
        faber.log(f"Average time per {item_long}: {avg:.2f}s ({1/avg:.2f}/s)")

        if alice.postgres:
            await alice.collect_postgres_stats(f"{issue_count} {item_short}s")
            for line in alice.format_postgres_stats():
                alice.log(line)
        if faber.postgres:
            await faber.collect_postgres_stats(f"{issue_count} {item_short}s")
            for line in faber.format_postgres_stats():
                faber.log(line)

        if revocation and faber.revocations:
            (rev_reg_id, cred_rev_id) = next(iter(faber.revocations))
            print(
                f"Revoking and publishing cred rev id {cred_rev_id} "
                f"from rev reg id {rev_reg_id}"
            )

        if show_timing:
            timing = await alice.fetch_timing()
            if timing:
                for line in alice.format_timing(timing):
                    alice.log(line)

            timing = await faber.fetch_timing()
            if timing:
                for line in faber.format_timing(timing):
                    faber.log(line)
            if mediation:
                timing = await alice_mediator_agent.fetch_timing()
                if timing:
                    for line in alice_mediator_agent.format_timing(timing):
                        alice_mediator_agent.log(line)
                timing = await faber_mediator_agent.fetch_timing()
                if timing:
                    for line in faber_mediator_agent.format_timing(timing):
                        faber_mediator_agent.log(line)

    finally:
        terminated = True
        try:
            if alice:
                await alice.terminate()
        except Exception:
            LOGGER.exception("Error terminating agent:")
            terminated = False
        try:
            if faber:
                await faber.terminate()
        except Exception:
            LOGGER.exception("Error terminating agent:")
            terminated = False
        try:
            if alice_mediator_agent:
                await alice_mediator_agent.terminate()
            if faber_mediator_agent:
                await faber_mediator_agent.terminate()
        except Exception:
            LOGGER.exception("Error terminating agent:")
            terminated = False

    run_timer.stop()
    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Runs an automated credential issuance performance demo."
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=300,
        help="Set the number of credentials to issue",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8030,
        metavar=("<port>"),
        help="Choose the starting port number to listen on",
    )
    parser.add_argument(
        "--ping",
        action="store_true",
        default=False,
        help="Only send ping messages between the agents",
    )
    parser.add_argument(
        "--multitenant", action="store_true", help="Enable multitenancy options"
    )
    parser.add_argument(
        "--mediation", action="store_true", help="Enable mediation functionality"
    )
    parser.add_argument(
        "--did-exchange",
        action="store_true",
        help="Use DID-Exchange protocol for connections",
    )
    parser.add_argument(
        "--proposal",
        action="store_true",
        default=False,
        help="Start credential exchange with a credential proposal from Alice",
    )
    parser.add_argument(
        "--revocation", action="store_true", help="Enable credential revocation"
    )
    parser.add_argument(
        "--tails-server-base-url",
        type=str,
        metavar="<tails-server-base-url>",
        help="Tails server base url",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Set the number of concurrent exchanges to start",
    )
    parser.add_argument(
        "--timing", action="store_true", help="Enable detailed timing report"
    )
    parser.add_argument(
        "--wallet-type",
        type=str,
        metavar="<wallet-type>",
        help="Set the agent wallet type",
    )
    args = parser.parse_args()

    if args.did_exchange and args.mediation:
        raise Exception(
            "DID-Exchange connection protocol is not (yet) compatible with mediation"
        )

    tails_server_base_url = args.tails_server_base_url or os.getenv("PUBLIC_TAILS_URL")

    if args.revocation and not tails_server_base_url:
        raise Exception(
            "If revocation is enabled, --tails-server-base-url must be provided"
        )
    action = "issue"
    if args.proposal:
        action = "propose"
    if args.ping:
        action = "ping"

    require_indy()

    try:
        asyncio.get_event_loop().run_until_complete(
            main(
                args.port,
                args.threads,
                action,
                args.timing,
                args.multitenant,
                args.mediation,
                args.did_exchange,
                args.revocation,
                tails_server_base_url,
                args.count,
                args.wallet_type,
            )
        )
    except KeyboardInterrupt:
        os._exit(1)
