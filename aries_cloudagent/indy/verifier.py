"""Base Indy Verifier class."""

import logging

from abc import ABC, ABCMeta, abstractmethod
from time import time
from typing import Mapping

from ..ledger.base import BaseLedger
from ..messaging.util import canon, encode
from ..protocols.present_proof.v1_0.util.indy import indy_proof_req2non_revoc_intervals

LOGGER = logging.getLogger(__name__)


class IndyVerifier(ABC, metaclass=ABCMeta):
    """Base class for Indy Verifier."""

    def __repr__(self) -> str:
        """
        Return a human readable representation of this class.

        Returns:
            A human readable string for this class

        """
        return "<{}>".format(self.__class__.__name__)

    def non_revoc_intervals(self, pres_req: dict, pres: dict):
        """
        Remove superfluous non-revocation intervals in presentation request.

        Irrevocable credentials constitute proof of non-revocation, but
        indy rejects proof requests with non-revocation intervals lining up
        with non-revocable credentials in proof: seek and remove.

        Args:
            pres_req: presentation request
            pres: corresponding presentation

        """
        for (req_proof_key, pres_key) in {
            "revealed_attrs": "requested_attributes",
            "revealed_attr_groups": "requested_attributes",
            "predicates": "requested_predicates",
        }.items():
            for (uuid, spec) in pres["requested_proof"].get(req_proof_key, {}).items():
                if (
                    pres["identifiers"][spec["sub_proof_index"]].get("timestamp")
                    is None
                ):
                    if pres_req[pres_key][uuid].pop("non_revoked", None):
                        LOGGER.info(
                            (
                                "Amended presentation request (nonce=%s): removed "
                                "non-revocation interval at %s referent "
                                "%s; corresponding credential in proof is irrevocable"
                            ),
                            pres_req["nonce"],
                            pres_key,
                            uuid,
                        )

        if all(spec.get("timestamp") is None for spec in pres["identifiers"]):
            pres_req.pop("non_revoked", None)
            LOGGER.warning(
                (
                    "Amended presentation request (nonce=%s); removed global "
                    "non-revocation interval; no revocable credentials in proof"
                ),
                pres_req["nonce"],
            )

    async def check_timestamps(
        self,
        ledger: BaseLedger,
        pres_req: Mapping,
        pres: Mapping,
        rev_reg_defs: Mapping,
    ):
        """
        Check for suspicious, missing, and superfluous timestamps.

        Raises ValueError on timestamp in the future, prior to rev reg creation,
        superfluous or missing.

        Args:
            ledger: the base ledger for retrieving revocation registry definitions
            pres_req: indy proof request
            pres: indy proof request
            rev_reg_defs: rev reg defs by rev reg id, augmented with transaction times
        """
        now = int(time())
        non_revoc_intervals = indy_proof_req2non_revoc_intervals(pres_req)

        # timestamp for irrevocable credential
        async with ledger:
            for (index, ident) in enumerate(pres["identifiers"]):
                if ident.get("timestamp"):
                    cred_def_id = ident["cred_def_id"]
                    cred_def = await ledger.get_credential_definition(cred_def_id)
                    if not cred_def["value"].get("revocation"):
                        raise ValueError(
                            f"Timestamp in presentation identifier #{index} "
                            f"for irrevocable cred def id {cred_def_id}"
                        )

        # timestamp in the future too far in the past
        for ident in pres["identifiers"]:
            timestamp = ident.get("timestamp")
            rev_reg_id = ident.get("rev_reg_id")

            if not timestamp:
                continue

            if timestamp > now + 300:  # allow 5 min for clock skew
                raise ValueError(f"Timestamp {timestamp} is in the future")
            if timestamp < rev_reg_defs[rev_reg_id]["txnTime"]:
                raise ValueError(
                    f"Timestamp {timestamp} predates rev reg {rev_reg_id} creation"
                )

        # timestamp superfluous, missing, or outside non-revocation interval
        revealed_attrs = pres["requested_proof"].get("revealed_attrs", {})
        revealed_groups = pres["requested_proof"].get("revealed_attr_groups", {})
        self_attested = pres["requested_proof"].get("self_attested_attrs", {})
        preds = pres["requested_proof"].get("predicates", {})
        for (uuid, req_attr) in pres_req["requested_attributes"].items():
            if "name" in req_attr:
                if uuid in revealed_attrs:
                    index = revealed_attrs[uuid]["sub_proof_index"]
                    timestamp = pres["identifiers"][index].get("timestamp")
                    if (timestamp is not None) ^ bool(non_revoc_intervals.get(uuid)):
                        raise ValueError(
                            f"Timestamp on sub-proof #{index} "
                            f"is {'superfluous' if timestamp else 'missing'} "
                            f"vs. requested attribute {uuid}"
                        )
                    if non_revoc_intervals.get(uuid) and not (
                        non_revoc_intervals[uuid].get("from", 0)
                        < timestamp
                        < non_revoc_intervals[uuid].get("to", now)
                    ):
                        LOGGER.info(
                            f"Timestamp {timestamp} from ledger for item"
                            f"{uuid} falls outside non-revocation interval "
                            f"{non_revoc_intervals[uuid]}"
                        )
                elif uuid not in self_attested:
                    raise ValueError(
                        f"Presentation attributes mismatch requested attribute {uuid}"
                    )

            elif "names" in req_attr:
                group_spec = revealed_groups.get(uuid)
                if (
                    group_spec is None
                    or "sub_proof_index" not in group_spec
                    or "values" not in group_spec
                ):
                    raise ValueError(f"Missing requested attribute group {uuid}")
                index = group_spec["sub_proof_index"]
                timestamp = pres["identifiers"][index].get("timestamp")
                if (timestamp is not None) ^ bool(non_revoc_intervals.get(uuid)):
                    raise ValueError(
                        f"Timestamp on sub-proof #{index} "
                        f"is {'superfluous' if timestamp else 'missing'} "
                        f"vs. requested attribute group {uuid}"
                    )
                if non_revoc_intervals.get(uuid) and not (
                    non_revoc_intervals[uuid].get("from", 0)
                    < timestamp
                    < non_revoc_intervals[uuid].get("to", now)
                ):
                    LOGGER.warning(
                        f"Timestamp {timestamp} from ledger for item"
                        f"{uuid} falls outside non-revocation interval "
                        f"{non_revoc_intervals[uuid]}"
                    )

        for (uuid, req_pred) in pres_req["requested_predicates"].items():
            pred_spec = preds.get(uuid)
            if pred_spec is None or "sub_proof_index" not in pred_spec:
                f"Presentation predicates mismatch requested predicate {uuid}"
            index = pred_spec["sub_proof_index"]
            timestamp = pres["identifiers"][index].get("timestamp")
            if (timestamp is not None) ^ bool(non_revoc_intervals.get(uuid)):
                raise ValueError(
                    f"Timestamp on sub-proof #{index} "
                    f"is {'superfluous' if timestamp else 'missing'} "
                    f"vs. requested predicate {uuid}"
                )
            if non_revoc_intervals.get(uuid) and not (
                non_revoc_intervals[uuid].get("from", 0)
                < timestamp
                < non_revoc_intervals[uuid].get("to", now)
            ):
                LOGGER.warning(
                    f"Best-effort timestamp {timestamp} "
                    "from ledger falls outside non-revocation interval "
                    f"{non_revoc_intervals[uuid]}"
                )

    async def pre_verify(self, pres_req: dict, pres: dict):
        """
        Check for essential components and tampering in presentation.

        Visit encoded attribute values against raw, and predicate bounds,
        in presentation, cross-reference against presentation request.

        Args:
            pres_req: presentation request
            pres: corresponding presentation

        """
        if not (
            pres_req
            and "requested_predicates" in pres_req
            and "requested_attributes" in pres_req
        ):
            raise ValueError("Incomplete or missing proof request")
        if not pres:
            raise ValueError("No proof provided")
        if "requested_proof" not in pres:
            raise ValueError("Presentation missing 'requested_proof'")
        if "proof" not in pres:
            raise ValueError("Presentation missing 'proof'")

        for (uuid, req_pred) in pres_req["requested_predicates"].items():
            try:
                canon_attr = canon(req_pred["name"])
                for ge_proof in pres["proof"]["proofs"][
                    pres["requested_proof"]["predicates"][uuid]["sub_proof_index"]
                ]["primary_proof"]["ge_proofs"]:
                    pred = ge_proof["predicate"]
                    if pred["attr_name"] == canon_attr:
                        if pred["value"] != req_pred["p_value"]:
                            raise ValueError(
                                f"Predicate value != p_value: {pred['attr_name']}"
                            )
                        break
                else:
                    raise ValueError(f"Missing requested predicate '{uuid}'")
            except (KeyError, TypeError):
                raise ValueError(f"Missing requested predicate '{uuid}'")

        revealed_attrs = pres["requested_proof"].get("revealed_attrs", {})
        revealed_groups = pres["requested_proof"].get("revealed_attr_groups", {})
        self_attested = pres["requested_proof"].get("self_attested_attrs", {})
        for (uuid, req_attr) in pres_req["requested_attributes"].items():
            if "name" in req_attr:
                if uuid in revealed_attrs:
                    pres_req_attr_spec = {req_attr["name"]: revealed_attrs[uuid]}
                elif uuid in self_attested:
                    if not req_attr.get("restrictions"):
                        continue
                    raise ValueError(
                        "Attribute with restrictions cannot be self-attested: "
                        f"'{req_attr['name']}'"
                    )
                else:
                    raise ValueError(
                        f"Missing requested attribute '{req_attr['name']}'"
                    )
            elif "names" in req_attr:
                group_spec = revealed_groups[uuid]
                pres_req_attr_spec = {
                    attr: {
                        "sub_proof_index": group_spec["sub_proof_index"],
                        **group_spec["values"].get(attr),
                    }
                    for attr in req_attr["names"]
                }
            else:
                raise ValueError(
                    f"Request attribute missing 'name' and 'names': '{uuid}'"
                )

            for (attr, spec) in pres_req_attr_spec.items():
                try:
                    primary_enco = pres["proof"]["proofs"][spec["sub_proof_index"]][
                        "primary_proof"
                    ]["eq_proof"]["revealed_attrs"][canon(attr)]
                except (KeyError, TypeError):
                    raise ValueError(f"Missing revealed attribute: '{attr}'")
                if primary_enco != spec["encoded"]:
                    raise ValueError(f"Encoded representation mismatch for '{attr}'")
                if primary_enco != encode(spec["raw"]):
                    raise ValueError(f"Encoded representation mismatch for '{attr}'")

    @abstractmethod
    def verify_presentation(
        self,
        presentation_request,
        presentation,
        schemas,
        credential_definitions,
        rev_reg_defs,
        rev_reg_entries,
    ):
        """
        Verify a presentation.

        Args:
            presentation_request: Presentation request data
            presentation: Presentation data
            schemas: Schema data
            credential_definitions: credential definition data
            rev_reg_defs: revocation registry definitions
            rev_reg_entries: revocation registry entries
        """
