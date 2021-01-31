"""Cache for multitenancy profiles."""

import logging
import sys
from collections import OrderedDict
from typing import Optional

from ..core.profile import Profile

LOGGER = logging.getLogger(__name__)


class ProfileCache:
    """Profile cache that caches based on LRU strategy."""

    def __init__(self, capacity: int):
        """Initialize ProfileCache.

        Args:
            capacity: The capacity of the cache. If capacity is exceeded
                      profiles are closed.
        """

        self.profiles: OrderedDict[str, Profile] = OrderedDict()
        self.capacity = capacity

    async def _cleanup(self):
        for (key, profile) in self.profiles.items():
            # When ref count is 4 we can assume the profile is not referenced
            # 1 = profiles dict
            # 2 = self.profiles.items()
            # 3 = profile above
            # 4 = sys.getrefcount
            if sys.getrefcount(profile) <= 4:
                LOGGER.debug(f"closing profile with id {key}")
                del self.profiles[key]
                await profile.close()

                if len(self.profiles) <= self.capacity:
                    break

    def get(self, key: str) -> Optional[Profile]:
        """Get profile with associated key from cache.

        Args:
            key (str): the key to get the profile for.

        Returns:
            Optional[Profile]: Profile if found in cache.

        """
        if key not in self.profiles:
            return None
        else:
            self.profiles.move_to_end(key)
            return self.profiles[key]

    def has(self, key: str) -> bool:
        """Check whether there is a profile with associated key in the cache.

        Args:
            key (str): the key to check for a profile

        Returns:
            bool: Whether the key exists in the cache

        """
        return key in self.profiles

    async def put(self, key: str, value: Profile) -> None:
        """Add profile with associated key to the cache.

        If new profile exceeds the cache capacity least recently used profiles
        that are not used will be removed from the cache.

        Args:
            key (str): the key to set
            value (Profile): the profile to set
        """
        self.profiles[key] = value
        self.profiles.move_to_end(key)
        LOGGER.debug(f"setting profile with id {key} in profile cache")

        if len(self.profiles) > self.capacity:
            LOGGER.debug(f"profile limit of {self.capacity} reached. cleaning...")
            await self._cleanup()

    def remove(self, key: str):
        """Remove profile with associated key from the cache.

        Args:
            key (str): The key to remove from the cache.
        """
        del self.profiles[key]
