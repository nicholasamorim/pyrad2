#!/usr/bin/python
from pyrad2 import dictionary, server
from pyrad2.constants import PacketType
from loguru import logger


class FakeServer(server.Server):
    def handle_auth_packet(self, pkt):
        logger.info("Received an authentication request")
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

        reply.code = PacketType.AccessAccept
        self.send_reply_packet(pkt.fd, reply)

    def handle_acct_packet(self, pkt):
        logger.info("Received an accounting request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.create_reply_packet(pkt)
        self.send_reply_packet(pkt.fd, reply)

    def handle_coa_packet(self, pkt):
        logger.info("Received an coa request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.create_reply_packet(pkt)
        self.send_reply_packet(pkt.fd, reply)

    def handle_disconnect_packet(self, pkt):
        logger.info("Received an disconnect request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.create_reply_packet(pkt)
        # COA NAK
        reply.code = 45
        self.send_reply_packet(pkt.fd, reply)


if __name__ == "__main__":
    # create server and read dictionary
    srv = FakeServer(dict=dictionary.Dictionary("dictionary"), coa_enabled=True)

    # add clients (address, secret, name)
    srv.hosts["127.0.0.1"] = server.RemoteHost(
        "127.0.0.1", b"Kah3choteereethiejeimaeziecumi", "localhost"
    )
    srv.bind_to_address("0.0.0.0")

    # start server
    srv.run()
