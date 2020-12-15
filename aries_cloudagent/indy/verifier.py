"""Base Indy Verifier class."""

import logging

from abc import ABC, ABCMeta, abstractmethod

from ..messaging.util import canon, encode

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
