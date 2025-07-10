#!/usr/bin/python
from pyrad2 import dictionary, server
from pyrad2.constants import PacketType
from loguru import logger


class FakeServer(server.Server):
    def HandleAuthPacket(self, pkt):
        logger.info("Received an authentication request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.CreateReplyPacket(
            pkt,
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "192.168.0.1",
                "Framed-IPv6-Prefix": "fc66::/64",
            },
        )

        reply.code = PacketType.AccessAccept
        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):
        logger.info("Received an accounting request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleCoaPacket(self, pkt):
        logger.info("Received an coa request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleDisconnectPacket(self, pkt):
        logger.info("Received an disconnect request")
        logger.info("Attributes: ")
        for attr in pkt.keys():
            logger.info("{}: {}", attr, pkt[attr])

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        self.SendReplyPacket(pkt.fd, reply)


if __name__ == "__main__":
    # create server and read dictionary
    srv = FakeServer(dict=dictionary.Dictionary("dictionary"), coa_enabled=True)

    # add clients (address, secret, name)
    srv.hosts["127.0.0.1"] = server.RemoteHost(
        "127.0.0.1", b"Kah3choteereethiejeimaeziecumi", "localhost"
    )
    srv.BindToAddress("0.0.0.0")

    # start server
    srv.Run()
