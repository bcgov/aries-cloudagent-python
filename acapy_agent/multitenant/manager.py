"""Manager for multitenancy."""

import logging
from typing import Iterable, Optional

from ..askar.profile_anon import AskarAnoncredsProfile
from ..config.injection_context import InjectionContext
from ..config.wallet import wallet_config
from ..core.profile import Profile
from ..multitenant.base import BaseMultitenantManager
from ..wallet.models.wallet_record import WalletRecord
from .cache import ProfileCache

LOGGER = logging.getLogger(__name__)


class MultitenantManager(BaseMultitenantManager):
    """Class for handling multitenancy."""

    def __init__(self, profile: Profile):
        """Initialize default multitenant Manager.

        Args:
            profile: The profile for this manager
        """
        super().__init__(profile)
        self._profiles = ProfileCache(
            profile.settings.get_int("multitenant.cache_size") or 100
        )

    @property
    def open_profiles(self) -> Iterable[Profile]:
        """Return iterator over open profiles."""
        yield from self._profiles.profiles.values()

    async def get_wallet_profile(
        self,
        base_context: InjectionContext,
        wallet_record: WalletRecord,
        extra_settings: Optional[dict] = None,
        *,
        provision=False,
    ) -> Profile:
        """Get profile for a wallet record.

        Args:
            base_context: Base context to extend from
            wallet_record: Wallet record to get the context for
            extra_settings: Any extra context settings
            provision: Whether to provision the wallet

        Returns:
            Profile: Profile for the wallet record

        """
        extra_settings = extra_settings or {}
        wallet_id = wallet_record.wallet_id
        profile = self._profiles.get(wallet_id)
        if not profile:
            # Extend base context
            context = base_context.copy()

            # Settings we don't want to use from base wallet
            reset_settings = {
                "wallet.recreate": False,
                "wallet.seed": None,
                "wallet.rekey": None,
                "wallet.name": None,
                "wallet.type": None,
                "mediation.open": None,
                "mediation.invite": None,
                "mediation.default_id": None,
                "mediation.clear": None,
            }
            extra_settings["admin.webhook_urls"] = self.get_webhook_urls(
                base_context, wallet_record
            )

            context.settings = (
                context.settings.extend(reset_settings)
                .extend(wallet_record.settings)
                .extend(extra_settings)
            )

            # MTODO: add ledger config
            profile, _ = await wallet_config(context, provision=provision)
            self._profiles.put(wallet_id, profile)

        # return anoncreds profile if explicitly set as wallet type
        if profile.context.settings.get("wallet.type") == "askar-anoncreds":
            return await AskarAnoncredsProfile.create(
                profile.opened,
                profile.context,
            )

        return profile

    async def update_wallet(self, wallet_id: str, new_settings: dict) -> WalletRecord:
        """Update an existing wallet and wallet record.

        Args:
            wallet_id: The wallet id of the wallet record
            new_settings: The context settings to be updated for this wallet

        Returns:
            WalletRecord: The updated wallet record

        """
        wallet_record = await super().update_wallet(wallet_id, new_settings)

        # Wallet record has been updated but profile settings in memory must
        # also be refreshed; update profile only if loaded
        profile = self._profiles.get(wallet_id)
        if profile:
            profile.settings.update(wallet_record.settings)

            extra_settings = {
                "admin.webhook_urls": self.get_webhook_urls(
                    self._profile.context, wallet_record
                ),
            }
            profile.settings.update(extra_settings)

        return wallet_record

    async def remove_wallet_profile(self, profile: Profile):
        """Remove the wallet profile instance.

        Args:
            profile: The wallet profile instance

        """
        wallet_id = profile.settings.get_str("wallet.id")
        self._profiles.remove(wallet_id)
        await profile.remove()
