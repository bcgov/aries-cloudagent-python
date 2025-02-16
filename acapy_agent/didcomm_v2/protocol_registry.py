"""Registry for DIDComm V2 Protocols."""

from ..utils.classloader import DeferLoad
from typing import Coroutine, Dict, Sequence, Union


class V2ProtocolRegistry:
    """DIDComm V2 Protocols."""

    def __init__(self):
        """Initialize a V2ProtocolRegistry instance."""
        self._type_to_message_handler: Dict[str, Coroutine] = {}

    @property
    def handlers(self) -> Dict[str, Coroutine]:
        """Accessor for a list of all message protocols."""
        return self._type_to_message_handler

    @property
    def protocols(self) -> Sequence[str]:
        """Accessor for a list of all message protocols."""
        return [str(key) for key in self._type_to_message_handler.keys()]

    def protocols_matching_query(self, query: str) -> Sequence[str]:
        """Return a list of message protocols matching a query string."""
        all_types = self.protocols
        result = None

        if query == "*" or query is None:
            result = all_types
        elif query:
            if query.endswith("*"):
                match = query[:-1]
                result = tuple(k for k in all_types if k.startswith(match))
            elif query in all_types:
                result = (query,)
        return result or ()

    def register_handler(self, message_type: str, handler: Union[Coroutine, str]):
        """Register a new message type to handler association."""
        if isinstance(handler, str):
            handler = DeferLoad(handler)
        self._type_to_message_handler[message_type] = handler
