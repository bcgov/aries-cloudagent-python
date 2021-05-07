# Intro
The author of this demo struggeled a bit with seeing the whole picture of the existing demoes. There were too much black box stuff going on for the author to understand what was exactly going on. Hence this demo was written while working out the kinks of whats what. This does not hide anything, do anything automatic and try take things from scratch so one understands how to set this up yourself. Initial conversation started here: https://github.com/hyperledger/aries-cloudagent-python/issues/983

# Pre configurations
## Docker and config
You need docker installed. Making sure that docker-compose also works on your end.
If you are unfamiliar with this, have a look at these two links: 

https://docs.docker.com/engine/install/ 
https://docs.docker.com/compose/install/

You also want to run the manage script with the function seed, to be able to get a seed to use in the configuration

`manage seed`

Use the outcome into `INDY_SEED` in the `.env` file
## Node and webhook receiver
Currently the webhook receiver is not setup for docker, so you have to have node to run it. Or you can contribute to the demo by wrapping it in a docker and adding it to the compose file.

But simply run   
`yarn`    
`yarn start`    
Or use npm if you prefer that

# Configurations
## .env
We have a .env file we need to fill in.
And then run the docker compose in the same folder as the .env file.

```
ADMIN_PORT=5000
AGENT_PORT=10000
INDY_SEED=diwala9jphVquhjphuVIerbf0XEc74WL
WEBHOOK_URL=http://host.docker.internal:3000/webhooks
AGENT_LABEL=Diwala Agent 3
LEDGER_URL=http://test.bcovrin.vonx.io
WALLETKEY=Diwala.Agent421311
MAIN_WALLET_NAME=diwala2
POSTGRES_ADMIN=admin-cloud-agent
POSTGRES_ADMIN_PASSWORD=testtest
POSTGRES_ACCOUNT=local-cloud-agent
POSTGRES_ACCOUNT_PASSWORD=testtest
```
From bottom to top. `Posgres` is explained below.  

`MAIN_WALLET_NAME` is in this multitenant setup, the multitenant wallet name.
`WALLETKEY` Got a question on that   
`LEDGER_URL` This is used inside docker compose for registering your seed, as well as using the same url to get the genesis block to connect to the ledger. This is a simple process because it is a testnet, might be a bit more difficult on production nets    
`AGENT_LABEL` Will just name the agent itself in the API and on the ledger. It is used for main outer agent in this multitenant setup     
`WEBHOOK_URL` Is important to define, what is the controller or webhook receiver for your agent? I have defined here a service that is simply spitting out the webhooks in the console. See the node folder    
`INDY_SEED` Explained in the top    
`AGENT_PORT` The port where the agent interacts   
`ADMIN_PORT` The port the admin interface, swagger api is available    

## Postgres
Postgres connection is important to make sure you are keeping state in a sane place. Volumes are fine, but they can be lost quite fast if it is not a good control over them. So a database, potentially as a service is even easier to handle and make sure that have the backups needed and overview needed.

Make an admin user that can create databases, put in `POSTGRES_ADMIN`   
Make a bit more restricte user that can read and write, put in `POSTGRES_ACCOUNT`

Go into the compose file and define a place your postgres is reachable. This example have a postgres running on the local machine, hence the `url: host.docker.internal:5432`

Looking at this, setting up configuration for postgres is quite straight forward, with one hickup. The above configuration does not work out of the box, atleast not on postgres < postgres@12.

The setup fails because it cannot find the a database with the name you defined of your admin “user”. Which is weird, as the user is not the database.

To get past this, I had to create a “fake” database with the defined “user” name and it was able to run initialisation and all for the rest of the indy database creation.

### Database management mode
It is important to be aware of what is default and what possibilities you have for database management mode. Here is an explainer: https://github.com/hyperledger/indy-sdk/tree/master/experimental/plugins/postgres_storage#wallet-management-modes
This example usess MultiWalletSingleTableSharedPool, see the compose file, because centralise all the things 🤪

### Statistics
If you want to have any insight to your data or statstics of what is going on, it is not possible to do so with the database entries. They are encrypted and done so for security reasons.

Suggestion is to have some audit loggin at the controller level. As when you set this to production, there will be some controller calling the agent API.

There is a new new storage mechanism that is coming, [Aries-Askar](https://github.com/hyperledger/aries-askar) which will have the capability of having a "null" encryption method. This is a security trade-off, being able to create better code as a developer vs. the risk of using null encryption in production.

### Questions
The crossed out is answered and documented
- ~~Is there any way to read out of the database and understand the binary data? Meaning setting up statistics towards the type column of a wallet db?~~
* When doing MultiWalletSingleTableSharedPool, why does it use the name wallets, and not the wallet name that the configuration sends in? There is an ID with the wallet name, but guess that is the multitenant wallet name one define then?
* What is exaclty wallet key?

# Creating connections
Following this very straight forward: https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#establishing-a-connection

Important notice, one thing that was not straight forward in the demo and this setup was: Response does not go to active by default. There has to be an action on the connection to make it in active state.
Trust ping or basic message pushes the state to active. But before that, it will stay response state. This is a response from the maintaners:
>This is for the initial connection method based [Aries RFC0160](https://github.com/hyperledger/aries-rfcs/tree/master/features/0160-connection-protocol). For the new [RFC0023 (DID Exchange)](https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange) mechanism, this will not be needed as there is an extra message in the protocol to ensure the connection is confirmed

# Sending a basic message
Follow this: https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#basic-messaging-between-agents

If you want messages to be stored, that has to be done through the controller and the webhook. Because the wallet dont store this, so it is your own responsibility to take action on that.

## Questions:
* I dont seem to get this event: Alice's Agent Verifies that Faber has Received the Message
That the message has been received by the agent, might this be a multitenant error? It is only one webhook message that it has been received on the recipient side.

# Issuance
As the demo says it does for you, setting up all for issuance: https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#preparing-to-issue-a-credential we will manually do here so we understand what is really behind this.

Lets say we are using this ledger: http://test.bcovrin.vonx.io/
According to your configuration from earlier, we are.

**PS:** No webhooks on the initial setup of schema and credential definition, so there might have to be a controller setup for controlling the creation of these schemas so that you can have some stats on it. Always possible to query all wallets, but that is not good. So at some of these controller endpoints, it will be smart to have some db storing, audit logging to make sure that we know what is happening.

## Creating the public did.
Then we first need to create a DID, we can also use the one created for your connection, but we want to keep things seperated and not nessecarily correlateable.
PS: Where the demo forces ngrok on you, so that you create an endpoint that is accessible by the web. But we dont need to consider this at the moment, because we are doing localhost, and endpoints can be rotated later when needed.

Create a did with `POST /wallet/did/create` [Localhost link to API doc](http://localhost:5000/api/doc#/wallet/post_wallet_did_create)

Go to http://test.bcovrin.vonx.io/, input the info from the response above.
Then go and assign the did you have created, and put on the ledger, as public: `POST /wallet/did/public` [Localhost link to API doc](http://localhost:5000/api/doc#/wallet/post_wallet_did_public)

**A public did we have!**
This can be done programatically and all, and is very dependent on the ledger you will be using.

All the next steps has to be done once, for each credential schema type. But once done for one credential type, you can issue as many as you want on that schema.

## Creating the schema
A schema is needed to make sure you know the attributes of a credential. This defines the names of the attributes and the schema, and also the version of the schema. Which is used in the credential definition
[Localhost link to API doc](http://localhost:5000/api/doc#/schema/post_schemas)

### Types
Currently the current stack is functionally complete. So types are not part of this stack. But there can come other VC supports in the future. Comment from maintaner:
> The Indy VC stack has been around for a long time and is functionally complete, but, as you note lacking in important areas like data types. We are currently working on adding support for VCs using JSON-LD and BBS+ Signatures. That will eliminate the need for an on-ledger schema (although that could be done) and for the credential definition (the keys for the cred def are dynamically derived from the issuer's key.

### Questions
* ~~Are there any work going on in defining types in the schema or what is the 2 cents there?~~

## Creating the credential definition 
This is where you define if you want revocation or not. It also where you define the definition of the credential, based on a schema. [Localhost link to API doc](http://localhost:5000/api/doc#/credential-definition/post_credential_definitions)

### Why
This follows the [AnonCreds design](https://hyperledger-indy.readthedocs.io/projects/sdk/en/latest/docs/design/002-anoncreds/README.html). The credential definition links the issuer of the credential to the ledger. Also links the schema and the public key of the issuer, so that there is a private key corresponding for each attribute.

This design also makes it easier to associate with the revocation registry.
Maintaner quote:
> In the AnonCreds verifiable credential mechanism -- the cred def links the issuer of the credential, the schema being used and contains a public key (and the issuer has the corresponding private key) for each attribute. As noted it also provides an association with the revocation registries.

### Questions
Why is this needed, except for revocation?

## Verify
By following this, you can verify that all is anchored to the ledger: https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#confirming-your-schema-and-credential-definition

# Issuance itself
We will support ourselves on this: https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#issuing-a-credential
Just add any extra info that is not clear to a totally new person.
We will go through both issuance v1.0 and v2.0 in the following text. Just to get the gist of the difference

Issuance goes through a protocol of steps that is important. The steps are lightly explained here: https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#alice-receives-credential
But with all the auto-flags you can set on the agents, you dont have to do these steps yourself. But with the current configuration, no auto-flags, we will do those going forward

## Defining the credential
### Using v1.0
Creating via the API, it gives you an example of attributes, they are explaned below.
It is not possible to send in mismatching attributes, the agent will complain and let you know. Just test it out.
There is 4 ways of doing this: **/create, /send, /send-proposal, /send-offer.** A questions is raised to learn what is the difference.
For now we will move onwards with send

#### Questions
* What is the difference between send and create? Also, send-offer and send-proposal? Is it related to the auto flags or? Since doing send, it was not automated.
* The example attributes defines a mime-type. What is this?
* What can be inside the value of an attribute? Only string?
* The type as a did:sov....spec before the url, what is this?
* If auto remove is false, where is it stored then? Kept in records forever?
* What is trace?
* Why do we need to define schema name over again, when we have the schema id there, with the name?
* What is needed of the difference between the issuer_did and the schema_issuer_did? To be able to use others schemas?

* When using send the comment is overridden by this comment: “create automated v1.0 credential exchange record”, why? And what preserves the comment? To the holder receiving the invitation?

Elaborate on all the attributes is needed. Dependent on the questions above.
```
{
  "auto_remove": true,
  "comment": "A proof of training from school of Faber",
  "connection_id": "909937cf-5753-43c3-90e7-c995c0fae644",
  "cred_def_id": "7ZMfiso8BCXMwSuUrnVGq3:3:CL:107621:main",
  "credential_proposal": {
    "@type": "issue-credential/1.0/credential-preview",
    "attributes": [
      {
        "mime-type": "image/jpeg",
        "name": "favourite_drink",
        "value": "martini"
      }
    ]
  },
  "issuer_did": "7ZMfiso8BCXMwSuUrnVGq3",
  "schema_id": "7ZMfiso8BCXMwSuUrnVGq3:2:ProofOfTraining:1.0",
  "schema_issuer_did": "7ZMfiso8BCXMwSuUrnVGq3",
  "schema_name": "ProofOfTraining",
  "schema_version": "1.0",
  "trace": false
}
```

**Auto remove:** It is a flag that tells the agent to remove the exchange record after the credential has been saved. Automatically. This way one does not have to fill up with credential exchanges while having the credential stored. But if you want to audit this trail, it has to be stored elsewhere, with this flag on. When the flag is, false, I have a question above.

### Using v2.0
This is very similar as v.1.0 so a questions is to find a pointer to the reasoning behind v2.0
But fill in the same attributes explained above, but inside the filter: indy attribute.

#### Questions
Are there any references to difference between v1.0 and v.2.0?
There is a new attribute, filter, and which introduces the dif and indy attributes, where can one read about that?


## Executing the offer credential
### Using v1
Executing the credential, after following: https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#issuing-a-credential
With the thoughts in the latter section.

It will send of two webhooks, one for the issuer, and one for the holder. Lots more data, but these are the most imporant things.
```
state: 'offer_sent',
role: 'issuer'

AND 

state: 'offer_received',
role: 'holder',
```
The request will also be available with the API for the holder, use the right version too look up the records. [Localhost link to API doc](http://localhost:5000/api/doc#/issue-credential%20v1.0/get_issue_credential_records)

#### Questions: 
What are the automation rules for this? Where do I set it per credential issunace? There were no flag, but maybe inside the JSON payload?

### Using v2
Not any difference in webhooks here, potentially data outside of this scope, and different api endpoints.

## Requesting credential on the offer
### Using v1
So since we dont have any automation flags setup in our configuration, and our request did not have any flags. We would have to request a credential on the offer. So on the holder side, we will execute [Localhost link to API doc](http://localhost:5000/api/doc#/issue-credential%20v1.0/post_issue_credential_records__cred_ex_id__send_request) with the ID from the offer. Can be see when requesting the available offers.

After this is executed there are four webhooks sent. Two for each connection ID with the following state. A lot more data is sent, but this is main info right now to understand the flow
```
role: 'holder',
state: 'request_sent'

state: 'request_received',
role: 'issuer'

state: 'credential_issued',
role: 'issuer',

state: 'credential_received',
role: 'holder',
```

That can be used for the state of the app to see that things are alll right!
Now the credential is issued, but still in offered situation.
We want to go to storage of the credential by the holder.
The holder has to call store

#### Questions:
* Why is auto issue suddenly turned on? What does that come from? 
```
state: 'request_sent',
role: 'holder',
initiator: 'external',
auto_issue: false,

Turns into this on the issuer side

state: 'credential_issued',
role: 'issuer',
initiator: 'self',
auto_issue: true,
```

### Using v2
This is the same, cannot say exactly about the data attributes but webhooks and events the same. And the questions from v1 stands still.

## Storing credential offer which has been issued
### Using v1
Before we can say that the credential is in our possession, we have to store it. If not it is still in an offer stage which will not work towards the credential request and queries.

Webhooks sent, a lot more data is sent, but this is main info right now to understand the flow:
```
  state: 'credential_acked',
  role: 'holder',

  state: 'credential_acked',
  role: 'issuer',
```

### Using v2
What this did a bit better was to set the state to done and clean up on both ends. Clean up the credentials exchange on both ends, because auto_remove was true.

# Present proof
After the credential has been issued and stored, someone wants to verify that credential. To do that they present a credential proof to the connection they already have to make sure that they have that credential.

## Creating the proof
A proof can consist of attributes or predicates.
Attributes being straigh up values, and predicates being something around a value. Bigger, lower, equal to and so on. Meaning that we only answer the question with a valid yes or no, not the truthy value.

The demo of aries has some good introducitons to this, but we need to populate some information from the demo, https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#requestingpresenting-a-proof

We will be using: `POST /present-proof/send-request`

## Setting up the proof request and send
To setup a proof request, we need to decide what we want to know, from what type of credential definitions available. To do this we have to then dig back to the credential definition we defined and issued earlier in the tutorial. You can look at holders credential, using: `GET /credential`, to get this data, or combine it with created credential definitions on the issuer side,   credential-definitions/created   `GET /credential-definitions/created`, with potentially records of credential exchanges, unless auto delete was on.

The demo showcases how to set it up properly
https://github.com/hyperledger/aries-cloudagent-python/blob/main/demo/AriesOpenAPIDemo.md#faber-sends-a-proof-request

Important to notice
`requested_predicates` is needed as an attribute, but can be empty, {}

When setup, it is just to hit execute. Be sure to validate your JSON, https://jsonlint.com/

Webhooks sent, a lot more data is sent, but this is main info right now to understand the flow:
```
  role: 'verifier',
  state: 'request_sent',

  role: 'prover',
  state: 'request_received',
```


### Questions
* The key for attributes, how to they work? What is important and no? 0_name_uuid? What is 0, name is the name of the attrbitue, and it is expected to add a unique identifier at the end?

## Holder responding to the Proof Request
So this can be set up as an automated process with flags on the agent, as mentioned before. Also what the demo is doing. But with this configuration we have to respond ourselves.

The first thing we can do is to check if the wallet has any credentials matching the request
`GET present-proof/records/{prex_ex_id}/credentials`

Here we can see the credentials that might match this request. Then it is down to selecting the different credentials. 

We use this endpoint: `GET /present-proof/records/{pres_ex_id}/send-presentation`

We fill the body by matching the requested attributes IDs, with the different credential IDs that was in the list above. Again, there are three potential data points here, where they have to be present, but empty to work. Sending off your specifc body 
Example body
```
{
  "requested_attributes": {
    "0_skill_uuid": {
      "cred_id": "551580e0-6055-4ce5-b5b2-9af910915bed",
      "revealed": true
    },
    "0_date_uuid": {
      "cred_id": "551580e0-6055-4ce5-b5b2-9af910915bed",
      "revealed": true
    },
    "0_name_uuid": {
      "cred_id": "551580e0-6055-4ce5-b5b2-9af910915bed",
      "revealed": true
    }
  },
  "requested_predicates": {},
  "self_attested_attributes":{},
  "trace": false
}
```

Webhooks sent, a lot more data is sent, but this is main info right now to understand the flow:
```
  role: 'prover',
  state: 'presentation_sent',

  role: 'verifier',
  state: 'presentation_received',
```

### Questions
* Can auto respond also be setup per request basis?
* Can I respond with different credential id values if I want to?
* Does it make sense to send multiple credentials at some point?
* What happens when revealed is false, what is the main usecase for that compared to predicates?

## Verifier verifying the Proof Request
Now that the presentation has been sent and received, the verifier can see its exchange in the endpoint `GET /present-proof/records` . The state is received but not verified. To do that, we take notice of the `presentation_exchange_id: 'dcf873e8-c3f7-46c4-ae42-94f14cfb9eff'`. And use that towards our next endpoint `POST /present-proof/records/{pres_ex_id}/verify-presentation`. 

When that post request is sent these webhooks are sent, a lot more data is sent, but this is main info right now to understand the flow:
```
  role: 'verifier',
  state: 'verified',

  role: 'prover',
  state: 'presentation_acked',
```

