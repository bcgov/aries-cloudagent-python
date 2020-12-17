"""Indy-Credx verifier implementation."""

import asyncio
import logging

from indy_credx import Presentation

from ...core.profile import Profile
from ...ledger.base import BaseLedger

from ..verifier import IndyVerifier

LOGGER = logging.getLogger(__name__)


class IndyCredxVerifier(IndyVerifier):
    """Indy-Credx verifier class."""

    def __init__(self, profile: Profile):
        """
        Initialize an IndyCredxVerifier instance.

        Args:
            profile: an active profile instance

        """
        self.ledger = profile.inject(BaseLedger)

    async def verify_presentation(
        self,
        pres_req,
        pres,
        schemas,
        credential_definitions,
        rev_reg_defs,
        rev_reg_entries,
    ) -> bool:
        """
        Verify a presentation.

        Args:
            pres_req: Presentation request data
            pres: Presentation data
            schemas: Schema data
            credential_definitions: credential definition data
            rev_reg_defs: revocation registry definitions
            rev_reg_entries: revocation registry entries
        """

        try:
            self.non_revoc_intervals(pres_req, pres)
            await self.check_timestamps(self.ledger, pres_req, pres, rev_reg_defs)
            await self.pre_verify(pres_req, pres)
        except ValueError as err:
            LOGGER.error(
                f"Presentation on nonce={pres_req['nonce']} "
                f"cannot be validated: {str(err)}"
            )
            return False

        try:
            presentation = Presentation.load(pres)
            verified = await asyncio.get_event_loop().run_in_executor(
                None,
                presentation.verify,
                pres_req,
                schemas.values(),
                credential_definitions.values(),
                rev_reg_defs.values(),
                rev_reg_entries,
            )
        except Exception:
            LOGGER.exception(
                f"Validation of presentation on nonce={pres_req['nonce']} "
                "failed with error"
            )
            verified = False

        return verified
