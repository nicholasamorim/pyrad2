import asyncio
import os

from loguru import logger

from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.packet import AcctPacket, AuthPacket, CoAPacket
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer
from pyrad2.server import RemoteHost


class RadSecServer(BaseRadSecServer):
    """A RADSEC server."""

    async def handle_access_request(self, packet: AuthPacket):
        logger.info("Received an authentication request with id {}", packet.id)
        logger.info("Secret {}", packet.secret)
        if packet.authenticator:
            logger.info("Authenticator {}", packet.authenticator.hex())

        for attr in packet.keys():
            logger.info("{}: {}", attr, packet[attr])

        reply = packet.CreateReply(
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "192.168.0.1",
                "Framed-IPv6-Prefix": "fc66::1/64",
            },
        )

        reply.code = PacketType.AccessAccept
        return reply

    async def handle_accounting(self, packet: AcctPacket):
        logger.info("Received an Accounting request. Attributes below")
        for attr in packet.keys():
            logger.info("{}: {}", attr, packet[attr])

        return packet.CreateReply()

    async def handle_disconnect(self, packet: CoAPacket):
        logger.info("Received an disconnect request. Attributes below")
        for attr in packet.keys():
            logger.info("{}: {}", attr, packet[attr])

        reply = packet.CreateReply()
        reply.code = 45  # COA NAK
        return reply

    async def handle_coa(self, packet: CoAPacket):
        logger.info("Received an coa request. Attributes below")
        for attr in packet.keys():
            logger.info("{}: {}", attr, packet[attr])

        return packet.CreateReply()


async def main():
    hosts = {
        "127.0.0.1": RemoteHost(name="localhost", address="127.0.0.1", secret=b"radsec")
    }

    current_folder = os.path.dirname(os.path.abspath(__file__))
    server = RadSecServer(
        hosts=hosts,
        dictionary=Dictionary("dictionary"),
        certfile=current_folder + "/certs/server/server.cert.pem",
        keyfile=current_folder + "/certs/server/server.key.pem",
        ca_certfile=current_folder + "/certs/ca/ca.cert.pem",
    )

    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
