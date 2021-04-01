"""Http outbound transport."""

import logging
from typing import Union

from aiohttp import ClientSession, DummyCookieJar, TCPConnector

from ...core.profile import Profile

from ..stats import StatsTracer
from ..wire_format import DIDCOMM_V0_MIME_TYPE, DIDCOMM_V1_MIME_TYPE

from .base import BaseOutboundTransport, OutboundTransportError


class HttpTransport(BaseOutboundTransport):
    """Http outbound transport class."""

    schemes = ("http", "https")

    def __init__(self) -> None:
        """Initialize an `HttpTransport` instance."""
        super().__init__()
        self.client_session: ClientSession = None
        self.connector: TCPConnector = None
        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the transport."""
        self.connector = TCPConnector(limit=200, limit_per_host=50)
        session_args = {
            "cookie_jar": DummyCookieJar(),
            "connector": self.connector,
            "trust_env": True,
        }
        if self.collector:
            session_args["trace_configs"] = [
                StatsTracer(self.collector, "outbound-http:")
            ]
        self.client_session = ClientSession(**session_args)
        return self

    async def stop(self):
        """Stop the transport."""
        await self.client_session.close()
        self.client_session = None

    async def handle_message(
        self,
        profile: Profile,
        payload: Union[str, bytes],
        endpoint: str,
        metadata: dict = None,
        api_key: str = None,
    ):
        """
        Handle message from queue.

        Args:
            profile: the profile that produced the message
            payload: message payload in string or byte format
            endpoint: URI endpoint for delivery
            metadata: Additional metadata associated with the payload
        """
        if not endpoint:
            raise OutboundTransportError("No endpoint provided")
        headers = metadata or {}
        if api_key is not None:
            headers["x-api-key"] = api_key
        if isinstance(payload, bytes):
            if profile.settings.get("aip_version", 1) >= 2:
                headers["Content-Type"] = DIDCOMM_V1_MIME_TYPE
            else:
                headers["Content-Type"] = DIDCOMM_V0_MIME_TYPE
        else:
            headers["Content-Type"] = "application/json"
        self.logger.debug(
            "Posting to %s; Data: %s; Headers: %s", endpoint, payload, headers
        )
        async with self.client_session.post(
            endpoint, data=payload, headers=headers
        ) as response:
            if response.status < 200 or response.status > 299:
                raise OutboundTransportError(
                    (
                        f"Unexpected response status {response.status}, "
                        f"caused by: {response.reason}"
                    )
                )
