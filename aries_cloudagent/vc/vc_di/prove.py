"""Verifiable Credential and Presentation proving methods."""

import asyncio
from hashlib import sha256
import time

from aries_cloudagent.anoncreds.models.anoncreds_revocation import (
    RevRegDef,
    RevRegDefValue,
)
from aries_cloudagent.anoncreds.revocation import AnonCredsRevocation
from ..ld_proofs import (
    AuthenticationProofPurpose,
    ProofPurpose,
    LinkedDataProofException,
)
from ...anoncreds.holder import AnonCredsHolder, AnonCredsHolderError
from ...anoncreds.verifier import AnonCredsVerifier
from ...core.profile import Profile
from anoncreds import (
    W3cCredential,
    RevocationStatusList,
    CredentialRevocationState,
    AnoncredsError,
)


async def create_signed_anoncreds_presentation(
    *,
    profile: Profile,
    pres_definition: dict,
    presentation: dict,
    credentials: list,
    purpose: ProofPurpose = None,
    challenge: str = None,
    domain: str = None,
    holder: bool = True,
) -> (dict, dict, dict):
    """Sign the presentation with the passed signature suite.

    Will set a default AuthenticationProofPurpose if no proof purpose is passed.

    Args:
        presentation (dict): The presentation to sign
        suite (LinkedDataProof): The signature suite to sign the presentation with
        document_loader (DocumentLoader): Document loader to use.
        purpose (ProofPurpose, optional): Purpose to use. Required if challenge is None
        challenge (str, optional): Challenge to use. Required if domain is None.
        domain (str, optional): Domain to use. Only used if purpose is None.

    Raises:
        LinkedDataProofException: When both purpose and challenge are not provided
            And when signing of the presentation fails

    Returns:
        dict: A verifiable presentation object

    """
    if not purpose and not challenge:
        raise LinkedDataProofException(
            'A "challenge" param is required when not providing a'
            ' "purpose" (for AuthenticationProofPurpose).'
        )
    if not purpose:
        purpose = AuthenticationProofPurpose(challenge=challenge, domain=domain)

    # validate structure of presentation
    pres_submission = presentation["presentation_submission"]
    descriptor_map = pres_submission["descriptor_map"]

    w3c_creds = []
    w3c_creds_metadata = []
    for credential in credentials:
        w3c_cred = W3cCredential.load(credential)
        w3c_creds.append(w3c_cred)
        w3c_creds_metadata.append({})

    pres_name = (
        pres_definition.get("name") if pres_definition.get("name") else "Proof request"
    )
    hash = sha256(challenge.encode("utf-8")).hexdigest()
    nonce = str(int(hash, 16))[:20]

    # assemble the necessary structures and then call
    # AnoncredsHolder.create_presentation_w3c() (new method)
    anoncreds_proofrequest = {
        "version": "1.0",
        "name": pres_name,
        "nonce": nonce,
        "requested_attributes": {},
        "requested_predicates": {},
    }

    non_revoked = int(time.time())
    non_revoked_interval = {"from": non_revoked, "to": non_revoked}

    for descriptor_map_item in descriptor_map:
        descriptor = next(
            item
            for item in pres_definition["input_descriptors"]
            if item["id"] == descriptor_map_item["id"]
        )

        referent = descriptor_map_item["id"]
        attribute_referent = f"{referent}_attribute"
        predicate_referent_base = f"{referent}_predicate"
        predicate_referent_index = 0
        # issuer_id = None

        fields = descriptor["constraints"]["fields"]
        statuses = descriptor["constraints"]["statuses"]

        # descriptor_map_item['path'] should be something
        # like '$.verifiableCredential[n]', we need to extract 'n'
        entry_idx = _extract_cred_idx(descriptor_map_item["path"])
        w3c_cred = w3c_creds[entry_idx]
        schema_id = w3c_cred.schema_id
        cred_def_id = w3c_cred.cred_def_id
        # rev_reg_id = w3c_cred.rev_reg_id
        # rev_reg_index = w3c_cred.rev_reg_index

        requires_revoc_status = "active" in statuses and statuses["active"][
            "directive"
        ] in ("allowed", "required")
        # TODO check that a revocation id is supplied if required
        # if requires_revoc_status and (not rev_reg_id):
        #     throw some kind of error

        w3c_creds_metadata[entry_idx] = {
            "schema_id": schema_id,
            "cred_def_id": cred_def_id,
            "revoc_status": non_revoked_interval if requires_revoc_status else None,
            "proof_attrs": [],
            "proof_preds": [],
        }

        if requires_revoc_status:
            w3c_creds_metadata[entry_idx]["rev_reg_id"] = w3c_cred.rev_reg_id
            w3c_creds_metadata[entry_idx]["timestamp"] = non_revoked  # missing

        for field in fields:
            path = field["path"][0]

            # check for credential attributes vs other
            if path.startswith("$.credentialSubject."):
                property_name = path.replace("$.credentialSubject.", "")
                if "predicate" in field:
                    # get predicate info
                    pred_filter = field["filter"]
                    (p_type, p_value) = _get_predicate_type_and_value(pred_filter)
                    pred_request = {
                        "name": property_name,
                        "p_type": p_type,
                        "p_value": p_value,
                        "restrictions": [{"cred_def_id": cred_def_id}],
                        "non_revoked": (
                            non_revoked_interval if requires_revoc_status else None
                        ),
                    }
                    predicate_referent = (
                        f"{predicate_referent_base}_{predicate_referent_index}"
                    )
                    predicate_referent_index = predicate_referent_index + 1
                    anoncreds_proofrequest["requested_predicates"][
                        predicate_referent
                    ] = pred_request
                    w3c_creds_metadata[entry_idx]["proof_preds"].append(
                        predicate_referent
                    )
                else:
                    # no predicate, just a revealed attribute
                    attr_request = {
                        "names": [property_name],
                        "restrictions": [{"cred_def_id": cred_def_id}],
                        "non_revoked": (
                            non_revoked_interval if requires_revoc_status else None
                        ),
                    }
                    # check if we already have this referent ...
                    if (
                        attribute_referent
                        in anoncreds_proofrequest["requested_attributes"]
                    ):
                        anoncreds_proofrequest["requested_attributes"][
                            attribute_referent
                        ]["names"].append(property_name)
                    else:
                        anoncreds_proofrequest["requested_attributes"][
                            attribute_referent
                        ] = attr_request
                        w3c_creds_metadata[entry_idx]["proof_attrs"].append(
                            attribute_referent
                        )
            elif path.endswith(".issuer"):
                # capture issuer - {'path': ['$.issuer'],
                # 'filter': {'type': 'string', 'const': '569XGicsXvYwi512asJkKB'}}
                # TODO prob not a general case
                # issuer_id = field["filter"]["const"]
                pass
            else:
                print("... skipping:", path)

    anoncreds_verifier = AnonCredsVerifier(profile)
    (
        schemas,
        cred_defs,
        rev_reg_defs,
        rev_reg_entries,
    ) = await anoncreds_verifier.process_pres_identifiers(w3c_creds_metadata)

    if rev_reg_defs:
        revreg_def_v = list(rev_reg_defs.values())[0]
        rev_reg_key = list(rev_reg_defs.keys())[0]

        rev_reg_def = {
            rev_reg_key: RevRegDef(
                issuer_id=revreg_def_v["issuerId"],
                cred_def_id=revreg_def_v["credDefId"],
                tag=revreg_def_v["tag"],
                value=RevRegDefValue(
                    public_keys=revreg_def_v["value"]["publicKeys"],
                    tails_hash=revreg_def_v["value"]["tailsHash"],
                    tails_location=revreg_def_v["value"]["tailsLocation"],
                    max_cred_num=revreg_def_v["value"]["maxCredNum"],
                ),
                type=revreg_def_v["revocDefType"],
            )
        }

        x = RevocationStatusList.load(
            list(list(rev_reg_entries.values())[0].values())[0]
        ).to_dict()

        del x["currentAccumulator"]

        rev_lists = {"e": list(x.values())}

        rev_lists["e"][2] = RevocationStatusList.load(
            list(list(rev_reg_entries.values())[0].values())[0]
        )

    # TODO use rev_reg_defs, rev_reg_entries to create revocation states ...
    # TODO possibly refactor this into a couple of methods -
    # one to create the proof request and another to sign it
    # (the holder flag is a bit of a hack)
    if holder:
        # TODO match up the parameters with what the function is expecting ...
        anoncreds_holder = AnonCredsHolder(profile)
        revocation = AnonCredsRevocation(profile)
        rev_state = None
        try:

            if rev_reg_defs:

                rev_reg_def = RevRegDef(
                    issuer_id=revreg_def_v["issuerId"],
                    cred_def_id=revreg_def_v["credDefId"],
                    tag=revreg_def_v["tag"],
                    value=RevRegDefValue(
                        public_keys=revreg_def_v["value"]["publicKeys"],
                        tails_hash=revreg_def_v["value"]["tailsHash"],
                        tails_location=revreg_def_v["value"]["tailsLocation"],
                        max_cred_num=revreg_def_v["value"]["maxCredNum"],
                    ),
                    type=revreg_def_v["revocDefType"],
                )
                tails_local_path = await revocation.get_or_fetch_local_tails_path(
                    rev_reg_def
                )
                rev_state = await asyncio.get_event_loop().run_in_executor(
                    None,
                    CredentialRevocationState.create,
                    rev_reg_def.serialize(),
                    RevocationStatusList.load(
                        list(list(rev_reg_entries.values())[0].values())[0]
                    ),
                    int(w3c_creds[0].rev_reg_index),
                    tails_local_path,
                )

                print(">>> rev_state:", rev_state)

        except AnoncredsError as err:
            raise AnonCredsHolderError("Error creating revocation state") from err
        anoncreds_proof = await anoncreds_holder.create_presentation_w3c(
            presentation_request=anoncreds_proofrequest,
            requested_credentials_w3c=w3c_creds,
            credentials_w3c_metadata=w3c_creds_metadata,
            schemas=schemas,
            credential_definitions=cred_defs,
            rev_states=rev_state,
        )

        # TODO any processing to put the returned proof into DIF format
        anoncreds_proof["presentation_submission"] = presentation[
            "presentation_submission"
        ]
    else:
        anoncreds_proof = None

    return (anoncreds_proofrequest, anoncreds_proof, w3c_creds_metadata)


def _extract_cred_idx(item_path: str) -> int:
    # TODO put in some logic here ...
    print(">>> TODO need to parse the index from this path:", item_path)
    return 0


def _get_predicate_type_and_value(pred_filter: dict) -> (str, str):
    supported_properties = {
        "exclusiveMinimum": ">",
        "exclusiveMaximum": "<",
        "minimum": ">=",
        "maximum": "<=",
    }

    # TODO handle multiple predicates?
    for key in pred_filter.keys():
        if key in supported_properties:
            return (supported_properties[key], pred_filter[key])

    # TODO more informative description
    raise Exception()
