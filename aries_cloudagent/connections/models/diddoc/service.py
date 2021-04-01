"""
DID Document Service classes.

Copyright 2017-2019 Government of Canada
Public Services and Procurement Canada - buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


from typing import List, Sequence, Union

from .util import canon_ref
from .publickey import PublicKey


class Service:
    """
    Service specification to embed in DID document.

    Retains DIDs as raw values (orientated toward indy-facing operations),
    everything else as URIs (oriented toward W3C-facing operations).
    """

    def __init__(
        self,
        did: str,
        ident: str,
        typ: str,
        recip_keys: Union[Sequence, PublicKey],
        routing_keys: Union[Sequence, PublicKey],
        endpoint: str,
        priority: int = 0,
    ):
        """
        Initialize the Service instance.

        Retain service specification particulars.

        Args:
            did: DID of DID document embedding service, specified raw
                (operation converts to URI)
            ident: identifier for service
            typ: service type
            recip_keys: recipient key or keys
            routing_keys: routing key or keys
            endpoint: service endpoint
            priority: service priority

        Raises:
            ValueError: on bad input controller DID

        """

        self._did = did
        self._id = canon_ref(self._did, ident, ";")
        self._type = typ
        self._recip_keys = (
            [recip_keys]
            if isinstance(recip_keys, PublicKey)
            else list(recip_keys)
            if recip_keys
            else None
        )
        self._routing_keys = (
            [routing_keys]
            if isinstance(routing_keys, PublicKey)
            else list(routing_keys)
            if routing_keys
            else None
        )
        self._endpoint = endpoint
        self._priority = priority

    @property
    def did(self) -> str:
        """Accessor for the DID value."""

        return self._did

    @property
    def id(self) -> str:
        """Accessor for the service identifier."""

        return self._id

    @property
    def type(self) -> str:
        """Accessor for the service type."""

        return self._type

    @property
    def recip_keys(self) -> List[PublicKey]:
        """Accessor for the recipient keys."""

        return self._recip_keys

    @property
    def routing_keys(self) -> List[PublicKey]:
        """Accessor for the routing keys."""

        return self._routing_keys

    @property
    def endpoint(self) -> str:
        """Accessor for the endpoint value."""

        return self._endpoint

    @property
    def priority(self) -> int:
        """Accessor for the priority value."""

        return self._priority

    def to_dict(self) -> dict:
        """Return dict representation of service to embed in DID document."""

        rv = {"id": self.id, "type": self.type, "priority": self.priority}
        if self.recip_keys:
            rv["recipientKeys"] = [k.value for k in self.recip_keys]
        if self.routing_keys:
            rv["routingKeys"] = [k.value for k in self.routing_keys]
        rv["serviceEndpoint"] = self.endpoint

        return rv
