from behave import given, when, then
import json
from time import sleep
import time

from bdd_support.agent_backchannel_client import (
    agent_container_register_did,
    agent_container_GET,
    agent_container_POST,
    read_schema_data,
    async_sleep,
    read_json_data,
)
from runners.agent_container import AgentContainer


# This step is defined in another feature file
# Given "Acme" and "Bob" have an existing connection


@when('"{agent_name}" has a DID with role "{did_role}"')
def step_impl(context, agent_name, did_role):
    agent = context.active_agents[agent_name]

    # create a new DID in the current wallet
    created_did = agent_container_POST(agent["agent"], "/wallet/did/create")

    # publish to the ledger with did_role
    registered_did = agent_container_register_did(
        agent["agent"],
        created_did["result"]["did"],
        created_did["result"]["verkey"],
        "ENDORSER" if did_role == "ENDORSER" else "",
    )

    # make the new did the wallet's public did
    created_did = agent_container_POST(
        agent["agent"],
        "/wallet/did/public",
        params={"did": created_did["result"]["did"]},
    )

    if not "public_dids" in context:
        context.public_dids = {}
    context.public_dids[did_role] = created_did["result"]["did"]


@when('"{agent_name}" connection has job role "{connection_job_role}"')
def step_impl(context, agent_name, connection_job_role):
    agent = context.active_agents[agent_name]

    # current connection_id for the selected agent
    connection_id = agent["agent"].agent.connection_id

    # set role for agent's connection
    print("Updating role for connection:", connection_id, connection_job_role)
    updated_connection = agent_container_POST(
        agent["agent"],
        "/transactions/" + connection_id + "/set-endorser-role",
        params={"transaction_my_job": connection_job_role},
    )

    # assert goodness
    assert updated_connection["transaction_my_job"] == connection_job_role
    async_sleep(1.0)


@when('"{agent_name}" connection sets endorser info')
def step_impl(context, agent_name):
    agent = context.active_agents[agent_name]

    # current connection_id for the selected agent
    connection_id = agent["agent"].agent.connection_id
    endorser_did = context.public_dids["ENDORSER"]

    updated_connection = agent_container_POST(
        agent["agent"],
        "/transactions/" + connection_id + "/set-endorser-info",
        params={"endorser_did": endorser_did},
    )

    # assert goodness
    assert updated_connection["endorser_did"] == endorser_did
    async_sleep(1.0)


@when('"{agent_name}" authors a schema transaction with {schema_name}')
def step_impl(context, agent_name, schema_name):
    agent = context.active_agents[agent_name]

    schema_info = read_schema_data(schema_name)
    connection_id = agent["agent"].agent.connection_id

    created_txn = agent_container_POST(
        agent["agent"],
        "/schemas",
        data=schema_info["schema"],
        params={"conn_id": connection_id, "create_transaction_for_endorser": "true"},
    )

    # assert goodness
    assert created_txn["txn"]["state"] == "transaction_created"
    if not "txn_ids" in context:
        context.txn_ids = {}
    context.txn_ids["AUTHOR"] = created_txn["txn"]["_id"]


@when('"{agent_name}" requests endorsement for the transaction')
def step_impl(context, agent_name):
    agent = context.active_agents[agent_name]

    async_sleep(1.0)
    txn_id = context.txn_ids["AUTHOR"]

    data = read_json_data("expires_time.json")

    requested_txn = agent_container_POST(
        agent["agent"],
        "/transactions/create-request",
        data=data,
        params={"tran_id": txn_id},
    )

    # assert goodness
    assert requested_txn["state"] == "request_sent"


@when('"{agent_name}" endorses the transaction')
def step_impl(context, agent_name):
    agent = context.active_agents[agent_name]

    txns = {"results": []}
    i = 5
    while 0 == len(txns["results"]) and i > 0:
        async_sleep(1.0)
        txns = agent_container_GET(agent["agent"], "/transactions")
        i = i - 1
    requested_txn = txns["results"][0]
    assert requested_txn["state"] == "request_received"
    txn_id = requested_txn["_id"]

    endorsed_txn = agent_container_POST(
        agent["agent"], "/transactions/" + txn_id + "/endorse"
    )

    assert endorsed_txn["state"] == "transaction_endorsed"


@then('"{agent_name}" can write the transaction to the ledger')
def step_impl(context, agent_name):
    agent = context.active_agents[agent_name]

    async_sleep(1.0)
    txns = agent_container_GET(agent["agent"], "/transactions")
    requested_txn = txns["results"][0]
    assert requested_txn["state"] == "transaction_endorsed"
    txn_id = requested_txn["_id"]

    written_txn = agent_container_POST(
        agent["agent"], "/transactions/" + txn_id + "/write"
    )

    assert written_txn["state"] == "transaction_acked"


@then('"{agent_name}" has written the schema {schema_name} to the ledger')
def step_impl(context, agent_name, schema_name):
    agent = context.active_agents[agent_name]

    schema_info = read_schema_data(schema_name)

    schemas = agent_container_GET(agent["agent"], "/schemas/created")
    assert len(schemas["schema_ids"]) == 1

    schema_id = schemas["schema_ids"][0]
    schema = agent_container_GET(agent["agent"], "/schemas/" + schema_id)

    # TODO assert goodness
