"""Utilities to deal with indy."""

from ....indy.holder import IndyHolder

from .pres_preview import IndyPresPreview


async def indy_proof_req_preview2indy_requested_creds(
    indy_proof_req: dict,
    preview: IndyPresPreview = None,
    *,
    holder: IndyHolder,
):
    """
    Build indy requested-credentials structure.

    Given input proof request and presentation preview, use credentials in
    holder's wallet to build indy requested credentials structure for input
    to proof creation.

    Args:
        indy_proof_req: indy proof request
        pres_preview: preview from presentation proposal, if applicable
        holder: holder injected into current context

    """
    req_creds = {
        "self_attested_attributes": {},
        "requested_attributes": {},
        "requested_predicates": {},
    }

    for (referent, req_item) in indy_proof_req["requested_attributes"].items():
        credentials = await holder.get_credentials_for_presentation_request_by_referent(
            presentation_request=indy_proof_req,
            referents=(referent,),
            start=0,
            count=100,
        )
        if not credentials:
            raise ValueError(
                "Could not automatically construct presentation for "
                + f"presentation request {indy_proof_req['name']}"
                + f":{indy_proof_req['version']} because referent "
                + f"{referent} did not produce any credentials."
            )

        # match returned creds against any preview values
        if len(credentials) == 1:
            cred_match = credentials[0]
        elif preview:
            reft = indy_proof_req["requested_attributes"][referent]
            names = [reft["name"]] if "name" in reft else reft.get("names")
            for cred in credentials:  # holder sorts by irrevocability, least referent
                if all(
                    preview.has_attr_spec(
                        cred_def_id=cred["cred_info"]["cred_def_id"],
                        name=name,
                        value=cred["cred_info"]["attrs"][name],
                    )
                    for name in names
                ):
                    cred_match = cred
                    break
            else:
                raise ValueError(
                    "Could not automatically construct presentation for "
                    + f"presentation request {indy_proof_req['name']}"
                    + f":{indy_proof_req['version']} because referent "
                    + f"{referent} did not produce any credentials matching "
                    + "proposed preview."
                )
        else:
            cred_match = credentials[0]  # holder sorts

        if "restrictions" in indy_proof_req["requested_attributes"][referent]:
            req_creds["requested_attributes"][referent] = {
                "cred_id": cred_match["cred_info"]["referent"],
                "revealed": True,
            }
        else:
            req_creds["self_attested_attributes"][referent] = cred_match["cred_info"][
                "attrs"
            ][indy_proof_req["requested_attributes"][referent]["name"]]

    for referent in indy_proof_req["requested_predicates"]:
        credentials = await holder.get_credentials_for_presentation_request_by_referent(
            presentation_request=indy_proof_req,
            referents=(referent,),
            start=0,
            count=100,
        )
        if not credentials:
            raise ValueError(
                "Could not automatically construct presentation for "
                + f"presentation request {indy_proof_req['name']}"
                + f":{indy_proof_req['version']} because predicate "
                + f"referent {referent} did not produce any credentials."
            )

        cred_match = credentials[0]  # holder sorts
        if "restrictions" in indy_proof_req["requested_predicates"][referent]:
            req_creds["requested_predicates"][referent] = {
                "cred_id": cred_match["cred_info"]["referent"],
                "revealed": True,
            }
        else:
            req_creds["self_attested_attributes"][referent] = cred_match["cred_info"][
                "attrs"
            ][indy_proof_req["requested_predicates"][referent]["name"]]

    return req_creds


def indy_proof_req2non_revoc_intervals(indy_proof_req: dict):
    """Return non-revocation intervals by requested item referent in proof request."""
    non_revoc_intervals = {}
    for req_item_type in ("requested_attributes", "requested_predicates"):
        for (reft, req_item) in indy_proof_req[req_item_type].items():
            interval = req_item.get(
                "non_revoked",
                indy_proof_req.get("non_revoked"),
            )
            if interval:
                fro = interval.get("from")
                to = interval.get("to")
                if (to is not None) and fro == to:
                    interval["from"] = 0  # accommodate indy-sdk verify=False if fro=to
            non_revoc_intervals[reft] = interval
    return non_revoc_intervals
