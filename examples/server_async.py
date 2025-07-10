#!/usr/bin/python

import asyncio
import traceback

from loguru import logger

from pyrad2.dictionary import Dictionary
from pyrad2.constants import PacketType
from pyrad2.server import RemoteHost
from pyrad2.server_async import ServerAsync


class FakeServer(ServerAsync):
    def __init__(self, dictionary):
        super().__init__(dictionary=dictionary, enable_pkt_verify=True, debug=True)

    def handle_auth_packet(self, protocol, pkt, addr):
        logger.info("Received an authentication request with id {}", pkt.id)
        logger.info("Authenticator {}", pkt.authenticator.hex())
        logger.info("Secret {}", pkt.secret)
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.create_reply_packet(
            pkt,
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "192.168.0.1",
                "Framed-IPv6-Prefix": "fc66::/64",
            },
        )

        reply.code = PacketType.AccessAccept
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        logger.info("Received an accounting request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.create_reply_packet(pkt)
        protocol.send_response(reply, addr)

    def handle_coa_packet(self, protocol, pkt, addr):
        logger.info("Received an coa request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.create_reply_packet(pkt)
        protocol.send_response(reply, addr)

    def handle_disconnect_packet(self, protocol, pkt, addr):
        logger.info("Received an disconnect request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.create_reply_packet(pkt)
        # COA NAK
        reply.code = 45
        protocol.send_response(reply, addr)


async def main():
    server = FakeServer(dictionary=Dictionary("dictionary"))
    server.hosts["127.0.0.1"] = RemoteHost(
        "127.0.0.1", b"Kah3choteereethiejeimaeziecumi", "localhost"
    )

    try:
        await server.initialize_transports(
            enable_auth=True, enable_acct=True, enable_coa=True
        )

        try:
            await asyncio.Future()  # run forever until cancelled or interrupted
        except KeyboardInterrupt:
            pass

    except Exception as exc:
        logger.error("Error: %s", exc)
        logger.error("\n".join(traceback.format_exc().splitlines()))
    finally:
        await server.deinitialize_transports()


if __name__ == "__main__":
    asyncio.run(main())
