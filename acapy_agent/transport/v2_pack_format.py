"""Standard packed message format class for DIDComm V2."""

import logging

try:
    from didcomm_messaging import DIDCommMessaging
    from didcomm_messaging.crypto.backend.askar import CryptoServiceError
except ImportError as err:
    raise ImportError("Install the didcommv2 extra to use this module.") from err

import json
from typing import Sequence, Tuple, Union

from ..core.profile import ProfileSession
from ..messaging.base_message import DIDCommVersion
from ..messaging.util import time_now
from ..wallet.base import BaseWallet
from ..wallet.error import WalletNotFoundError
from .error import WireFormatParseError
from .inbound.receipt import MessageReceipt
from .wire_format import BaseWireFormat

LOGGER = logging.getLogger(__name__)


class V2PackWireFormat(BaseWireFormat):
    """DIDComm V2 message parser and serializer."""

    async def parse_message(
        self,
        session: ProfileSession,
        message_body: Union[str, bytes],
    ) -> Tuple[dict, MessageReceipt]:
        """Parse message."""

        messaging = session.inject(DIDCommMessaging)

        receipt = MessageReceipt()
        receipt.in_time = time_now()
        receipt.raw_message = message_body
        receipt.didcomm_version = DIDCommVersion.v2

        message_dict = None
        message_json = message_body

        if not message_json:
            raise WireFormatParseError("Message body is empty")

        try:
            message_dict = json.loads(message_json)
        except ValueError:
            raise WireFormatParseError("Message JSON parsing failed")
        if not isinstance(message_dict, dict):
            raise WireFormatParseError("Message JSON result is not an object")

        wallet = session.inject_or(BaseWallet)
        if not wallet:
            LOGGER.error("No wallet found")
            raise WalletNotFoundError()

        # packed messages are detected by the absence of type
        if "type" not in message_dict:
            try:
                message_unpack = await messaging.unpack(message_json)
            except CryptoServiceError:
                LOGGER.info("Message unpack failed, falling back to JSON")
            else:
                # Set message_dict to be the dictionary that we unpacked
                message_dict = message_unpack.message

                if message_unpack.sender_kid:
                    receipt.sender_verkey = message_unpack.sender_kid
                    receipt.recipient_verkey = message_unpack.recipient_kid

        thid = message_dict.get("thid")
        receipt.thread_id = thid or message_dict.get("id")

        receipt.parent_thread_id = message_dict.get("pthid")

        # handle transport decorator
        receipt.direct_response_mode = message_dict.get("return_route")

        LOGGER.debug("Expanded message: %s", message_dict)

        return message_dict, receipt

    async def encode_message(
        self,
        session: ProfileSession,
        message_json: Union[str, bytes],
        recipient_keys: Sequence[str],
        routing_keys: Sequence[str],
        sender_key: str,
    ) -> Union[str, bytes]:
        """Encode an outgoing message for transport.

        Args:
            session: The profile session for providing wallet access
            message_json: The message body to serialize
            recipient_keys: A sequence of recipient verkeys
            routing_keys: A sequence of routing verkeys
            sender_key: The verification key of the sending agent

        Returns:
            The encoded message

        Raises:
            MessageEncodeError: If the message could not be encoded

        """
        messaging = session.inject(DIDCommMessaging)

        if sender_key and recipient_keys:
            message = await messaging.pack(
                message=message_json,
                to=recipient_keys[0].split("#")[0],
                frm=sender_key.split("#")[0],
            )
            message = message.message
        else:
            message = message_json
        return message
