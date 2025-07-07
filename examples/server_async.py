#!/usr/bin/python

import asyncio
import traceback

from loguru import logger

from pyrad2.dictionary import Dictionary
from pyrad2.packet import AccessAccept
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
                "Framed-IPv6-Prefix": "fc66::1/64",
            },
        )

        reply.code = AccessAccept
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


if __name__ == "__main__":
    # create server and read dictionary
    loop = asyncio.get_event_loop()
    server = FakeServer(dictionary=Dictionary("dictionary"))

    # add clients (address, secret, name)
    server.hosts["127.0.0.1"] = RemoteHost(
        "127.0.0.1", b"Kah3choteereethiejeimaeziecumi", "localhost"
    )

    try:
        # Initialize transports
        loop.run_until_complete(
            asyncio.ensure_future(
                server.initialize_transports(
                    enable_auth=True, enable_acct=True, enable_coa=True
                )
            )
        )

        try:
            # start server
            loop.run_forever()
        except KeyboardInterrupt:
            pass

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(server.deinitialize_transports()))

    except Exception as exc:
        logger.error("Error: {}", exc)
        logger.error("\n".join(traceback.format_exc().splitlines()))
        # Close transports
        loop.run_until_complete(asyncio.ensure_future(server.deinitialize_transports()))

    loop.close()
