"""Indy-Credx verifier implementation."""

import asyncio
import logging

from indy_credx import Presentation

from ...core.profile import Profile
from ...ledger.base import BaseLedger

from ..verifier import IndyVerifier, PreVerifyResult

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
        presentation_request,
        presentation,
        schemas,
        credential_definitions,
        rev_reg_defs,
        rev_reg_entries,
    ) -> bool:
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

        self.non_revoc_intervals(presentation_request, presentation)

        (pv_result, pv_msg) = await self.pre_verify(presentation_request, presentation)
        if pv_result != PreVerifyResult.OK:
            LOGGER.error(
                f"Presentation on nonce={presentation_request['nonce']} "
                f"cannot be validated: {pv_result.value} [{pv_msg}]"
            )
            return False

        try:
            presentation = Presentation.load(presentation)
            verified = await asyncio.get_event_loop().run_in_executor(
                None,
                presentation.verify,
                presentation_request,
                schemas.values(),
                credential_definitions.values(),
                rev_reg_defs.values(),
                rev_reg_entries,
            )
        except Exception:
            LOGGER.exception(
                f"Validation of presentation on nonce={presentation_request['nonce']} "
                "failed with error"
            )
            verified = False

        return verified
