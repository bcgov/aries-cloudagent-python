"""Verifiable Credential and Presentation proving methods."""

import asyncio
import logging
import re
from hashlib import sha256
from typing import Any, Optional, Tuple

from anoncreds import (
    AnoncredsError,
    CredentialRevocationState,
    RevocationStatusList,
    W3cCredential,
)

from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.revocation.models.revocation_registry import RevocationRegistry

from ...anoncreds.holder import AnonCredsHolder, AnonCredsHolderError
from ...anoncreds.verifier import AnonCredsVerifier
from ...core.profile import Profile
from ..ld_proofs import LinkedDataProofException, ProofPurpose

LOGGER = logging.getLogger(__name__)


async def create_signed_anoncreds_presentation(
    *,
    profile: Profile,
    pres_definition: dict,
    presentation: dict,
    credentials: list,
    purpose: Optional[ProofPurpose] = None,
    challenge: str,
    domain: Optional[str] = None,
) -> tuple[dict, dict, list]:
    """Sign the presentation with the passed signature suite.

    Will set a default AuthenticationProofPurpose if no proof purpose is passed.

    Args:
        profile (Profile): The profile to use
        pres_definition (dict): The presentation definition
        presentation (dict): The presentation to sign
        credentials (list): The credentials to use for the presentation
        document_loader (DocumentLoader): Document loader to use.
        purpose (ProofPurpose, optional): Purpose to use. Required if challenge is None
        challenge (str, optional): Challenge to use. Required if domain is None.
        domain (str, optional): Domain to use. Only used if purpose is None.
        holder (bool, optional): create a presentation or just the proof request

    Raises:
        LinkedDataProofException: When both purpose and challenge are not provided
            And when signing of the presentation fails

    Returns:
        dict: A verifiable presentation object

    """

    if not challenge:
        raise LinkedDataProofException(
            'A "challenge" param is required when not providing a'
            ' "purpose" (for AuthenticationProofPurpose).'
        )

    w3c_creds = await _load_w3c_credentials(credentials)
    anoncreds_proofrequest, w3c_creds_metadata = await prepare_data_for_presentation(
        presentation, w3c_creds, pres_definition, profile, challenge
    )

    anoncreds_verifier = AnonCredsVerifier(profile)
    (
        schemas,
        cred_defs,
        rev_reg_defs,
        rev_reg_entries,
    ) = await anoncreds_verifier.process_pres_identifiers(w3c_creds_metadata)

    rev_states = await create_rev_states(
        w3c_creds_metadata, rev_reg_defs, rev_reg_entries
    )
    anoncreds_holder = AnonCredsHolder(profile)
    anoncreds_proof = await anoncreds_holder.create_presentation_w3c(
        presentation_request=anoncreds_proofrequest,
        requested_credentials_w3c=w3c_creds,
        credentials_w3c_metadata=w3c_creds_metadata,
        schemas=schemas,
        credential_definitions=cred_defs,
        rev_states=rev_states,
    )

    # TODO any processing to put the returned proof into DIF format
    anoncreds_proof["presentation_submission"] = presentation["presentation_submission"]

    return anoncreds_proof


async def _load_w3c_credentials(credentials: list) -> list:
    """_load_w3c_credentials.

    Args:
        credentials (list): The credentials to load

    Returns:
        list: A list of W3C credentials
    """
    w3c_creds = []
    for credential in credentials:
        try:
            w3c_cred = W3cCredential.load(credential)
            w3c_creds.append(w3c_cred)
        except Exception as err:
            raise LinkedDataProofException(
                "Error loading credential as W3C credential"
            ) from err

    return w3c_creds


async def create_rev_states(
    w3c_creds_metadata: list,
    rev_reg_defs: dict,
    rev_reg_entries: dict,
) -> Optional[dict]:
    """create_rev_states.

    Args:
        profile (Profile): The profile to use
        w3c_creds_metadata (list): The metadata for the credentials
        rev_reg_defs (dict): The revocation registry definitions
        rev_reg_entries (dict): The revocation registry entries

    Returns:
        dict: A dictionary of revocation states
    """
    if not bool(rev_reg_defs and rev_reg_entries):
        return None

    rev_states = {}
    for w3c_cred_cred in w3c_creds_metadata:
        rev_reg_def = rev_reg_defs.get(w3c_cred_cred["rev_reg_id"])
        rev_reg_def["id"] = w3c_cred_cred["rev_reg_id"]
        rev_reg_def_from_registry = RevocationRegistry.from_definition(rev_reg_def, True)
        local_tails_path = await rev_reg_def_from_registry.get_or_fetch_local_tails_path()
        revocation_status_list = RevocationStatusList.load(
            rev_reg_entries.get(w3c_cred_cred["rev_reg_id"])[
                w3c_cred_cred.get("timestamp")
            ]
        )
        rev_reg_index = w3c_cred_cred["rev_reg_index"]
        try:
            rev_state = await asyncio.get_event_loop().run_in_executor(
                None,
                CredentialRevocationState.create,
                rev_reg_def,
                revocation_status_list,
                rev_reg_index,
                local_tails_path,
            )
            rev_states[w3c_cred_cred["rev_reg_id"]] = rev_state
        except AnoncredsError as err:
            raise AnonCredsHolderError("Error creating revocation state") from err

    return rev_states


async def prepare_data_for_presentation(
    presentation,
    w3c_creds,
    pres_definition,
    profile,
    challenge,
) -> tuple[dict[str, Any], list, list]:
    """prepare_data_for_presentation.

    Args:
        presentation (dict): The presentation to prepare
        w3c_creds (list): The W3C credentials
        pres_definition (dict): The presentation definition
        profile (Profile): The profile to use
        challenge (str): The challenge to use

    Returns:
        tuple[dict[str, Any], list, list]: A tuple of the anoncreds proof
            request, the W3C credentials metadata, and the W3C credentials
    """

    if not challenge:
        raise LinkedDataProofException("A challenge is required")

    pres_submission = presentation["presentation_submission"]
    descriptor_map = pres_submission["descriptor_map"]
    w3c_creds_metadata = [{} for _ in range(len(w3c_creds))]
    pres_name = (
        pres_definition.get("name") if pres_definition.get("name") else "Proof request"
    )
    challenge_hash = sha256(challenge.encode("utf-8")).hexdigest()
    nonce = str(int(challenge_hash, 16))[:20]

    anoncreds_proofrequest = {
        "version": "1.0",
        "name": pres_name,
        "nonce": nonce,
        "requested_attributes": {},
        "requested_predicates": {},
    }

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

        fields = descriptor["constraints"]["fields"]
        statuses = descriptor["constraints"]["statuses"]

        # descriptor_map_item['path'] should be something
        # like '$.verifiableCredential[n]', we need to extract 'n'
        entry_idx = _extract_cred_idx(descriptor_map_item["path"])
        w3c_cred = w3c_creds[entry_idx]
        schema_id = w3c_cred.schema_id
        cred_def_id = w3c_cred.cred_def_id

        requires_revoc_status = "active" in statuses and statuses["active"][
            "directive"
        ] in ("allowed", "required")

        non_revoked_interval = None
        if requires_revoc_status and w3c_cred.rev_reg_id:
            anoncreds_registry = profile.inject(AnonCredsRegistry)

            result = await anoncreds_registry.get_revocation_list(
                profile, w3c_cred.rev_reg_id, None
            )
            w3c_creds_metadata[entry_idx]["rev_reg_id"] = w3c_cred.rev_reg_id
            w3c_creds_metadata[entry_idx]["timestamp"] = result.revocation_list.timestamp

            non_revoked_interval = {
                "from": result.revocation_list.timestamp,
                "to": result.revocation_list.timestamp,
            }
            w3c_creds_metadata[entry_idx]["rev_reg_index"] = w3c_cred.rev_reg_index
            w3c_creds_metadata[entry_idx]["revoc_status"] = non_revoked_interval

        w3c_creds_metadata[entry_idx]["schema_id"] = schema_id
        w3c_creds_metadata[entry_idx]["cred_def_id"] = cred_def_id
        w3c_creds_metadata[entry_idx]["proof_attrs"] = []
        w3c_creds_metadata[entry_idx]["proof_preds"] = []

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
                    anoncreds_proofrequest["requested_predicates"][predicate_referent] = (
                        pred_request
                    )
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
                LOGGER.info("... skipping: %s", path)

    return anoncreds_proofrequest, w3c_creds_metadata


def _extract_cred_idx(item_path: str) -> int:
    """_extract_cred_idx.

    Args:
        item_path (str): path to extract index from

    Raises:
        Exception: No index found in path

    Returns:
        int: extracted index
    """
    match = re.search(r"\[(\d+)\]", item_path)
    if match:
        return int(match.group(1))
    else:
        raise AnonCredsHolderError("No index found in path")


def _get_predicate_type_and_value(pred_filter: dict) -> Tuple[str, str]:
    """_get_predicate_type_and_value.

    Args:
        pred_filter (dict): predicate filter

    Raises:
        Exception: TODO

    Returns:
        Tuple[str, str]: predicate type and value
    """

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
    raise AnonCredsHolderError("Unsupported predicate filter")
