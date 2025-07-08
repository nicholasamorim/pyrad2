from loguru import logger

from pyrad2.packet import AccessAccept, AcctPacket, AuthPacket, CoAPacket
from pyrad2.server_radsec import RadSecServer


class RadiusServer(RadSecServer):
    """A RADSEC server."""

    async def handle_access_request(self, packet: AuthPacket):
        logger.info("Received an authentication request with id {}", packet.id)
        logger.info("Secret {}", packet.secret)
        if packet.authenticator:
            logger.info("Authenticator {}", packet.authenticator.hex())

        for attr in packet.keys():
            logger.info("{}: {}", attr, packet[attr])

        reply = packet.create_reply(
            packet,
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "192.168.0.1",
                "Framed-IPv6-Prefix": "fc66::1/64",
            },
        )

        reply.code = AccessAccept
        return reply

    async def handle_accounting(self, packet: AcctPacket):
        logger.info("Received an Accounting request. Attributes below")
        for attr in packet.keys():
            logger.info("{}: {}", attr, packet[attr])

        return packet.create_reply()

    async def handle_disconnect(self, packet: CoAPacket):
        logger.info("Received an disconnect request. Attributes below")
        for attr in packet.keys():
            logger.info("{}: {}", attr, packet[attr])

        reply = packet.create_reply()
        reply.code = 45  # COA NAK
        return reply

    async def handle_coa(self, packet: CoAPacket):
        logger.info("Received an coa request. Attributes below")
        for attr in packet.keys():
            logger.info("{}: {}", attr, packet[attr])

        return packet.create_reply()
