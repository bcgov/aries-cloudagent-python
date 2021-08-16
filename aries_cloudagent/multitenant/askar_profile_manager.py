"""Manager for multitenancy."""

import logging

from ..core.profile import (
    Profile,
)
from ..config.wallet import wallet_config
from ..config.injection_context import InjectionContext
from ..wallet.models.wallet_record import WalletRecord
from ..askar.profile import AskarProfile
from ..multitenant.base import BaseMultitenantManager

LOGGER = logging.getLogger(__name__)


class AskarProfileMultitenantManager(BaseMultitenantManager):
    """Class for handling askar profile multitenancy."""
    DEFAULT_MULTIENANT_WALLET_NAME = "multitenant-wallet"

    def __init__(self, profile: Profile):
        """Initialize askar profile multitenant Manager.

        Args:
            profile: The profile for this manager
        """
        super().__init__(profile)

    async def get_wallet_profile(
        self,
        base_context: InjectionContext,
        wallet_record: WalletRecord,
        extra_settings: dict = {},
        *,
        provision=False,
    ) -> Profile:
        """Get profile for a wallet record.

        Args:
            base_context: Base context to extend from
            wallet_record: Wallet record to get the context for
            extra_settings: Any extra context settings

        Returns:
            Profile: Profile for the wallet record

        """
        context = base_context.copy()

        multitenant_wallet_name = context.settings.get("multitenant.wallet.name") or self.DEFAULT_MULTIENANT_WALLET_NAME

        if multitenant_wallet_name not in self._instances:
            # Settings we don't want to use from base wallet
            reset_settings = {
                "wallet.recreate": False,
                "wallet.seed": None,
                "wallet.rekey": None,
                "wallet.id": None,
                "wallet.name": multitenant_wallet_name,
                "wallet.type": "askar",
                "mediation.open": None,
                "mediation.invite": None,
                "mediation.default_id": None,
                "mediation.clear": None,
                "auto_provision": True,
            }
            context.settings = (context.settings.extend(reset_settings))

            profile, _ = await wallet_config(context, provision=False)
            self._instances[multitenant_wallet_name] = profile

        multitenant_wallet = self._instances[multitenant_wallet_name]

        if provision:
            multitenant_wallet.store.create_profile(wallet_record.wallet_id)

        extra_settings["admin.webhook_urls"] = self.get_webhook_urls(
            base_context, wallet_record
        )
        context.settings = (context.settings.extend(wallet_record.settings).extend(extra_settings))

        return AskarProfile(multitenant_wallet, context)
