import os
import unittest

from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.radsec.client import RadSecClient
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer
from pyrad2.radsec.server import UnknownHost
from pyrad2.server import RemoteHost

from .base import TEST_ROOT_PATH

TEST_HOST = RemoteHost(
    "name",
    b"radsec",
    "127.0.0.1",
)

SERVER_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/server/server.cert.pem")
SERVER_KEYFILE = os.path.join(TEST_ROOT_PATH, "certs/server/server.key.pem")
CA_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/ca/ca.cert.pem")
CLIENT_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/client/client.cert.pem")
CLIENT_KEYFILE = os.path.join(TEST_ROOT_PATH, "certs/client/client.key.pem")


class RemoteHostTests(unittest.TestCase):
    def test_simple_construction(self):
        host = RemoteHost(
            "127.0.0.1",
            b"radsec",
            "name",
        )
        self.assertEqual(host.name, "name")
        self.assertEqual(host.address, "127.0.0.1")
        self.assertEqual(host.secret, b"radsec")


class RadSecServer(BaseRadSecServer):
    async def handle_access_request(self, packet):
        reply = packet.CreateReply(
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "192.168.0.1",
                "Framed-IPv6-Prefix": "fc66::1/64",
            },
        )

        reply.code = PacketType.AccessAccept
        return reply

    async def handle_accounting(self, packet):
        return packet.CreateReply()

    async def handle_disconnect(self, packet):
        reply = packet.CreateReply()
        reply.code = 45  # COA NAK
        return reply

    async def handle_coa(self, packet):
        return packet.CreateReply()


class ServerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dictionary = Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary"))

        self.server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
        )
        self.server.hosts = {"127.0.0.1": TEST_HOST}

        self.client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
        )

    def test_simple_construction(self):
        self.assertEqual(self.server.listen_address, "0.0.0.0")
        self.assertEqual(self.server.listen_port, 2083)
        self.assertEqual(self.server.hosts, {"127.0.0.1": TEST_HOST})
        self.assertEqual(self.server.dict, self.dictionary)
        self.assertEqual(self.server.verify_packet, False)

    async def test_unknown_host(self):
        with self.assertRaises(UnknownHost):
            await self.server.packet_received({}, "4.4.4.4")


class AuthPacketHandlingTests(ServerTests):
    def setUp(self):
        super().setUp()
        self.packet = self.create_auth_packet()

    def create_auth_packet(self):
        packet = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="wichert"
        )
        packet["NAS-IP-Address"] = "192.168.1.10"
        packet["NAS-Port"] = 0
        packet["Service-Type"] = "Login-User"
        packet["NAS-Identifier"] = "trillian"
        packet["Called-Station-Id"] = "00-04-5F-00-0F-D1"
        packet["Calling-Station-Id"] = "00-01-24-80-B3-9C"
        packet["Framed-IP-Address"] = "10.0.0.100"
        return packet

    async def test_handle_auth_packet(self):
        reply = await self.server.handle_access_request(self.packet)
        self.assertEqual(reply.code, PacketType.AccessAccept)


class AcctPacketHandlingTests(ServerTests):
    def setUp(self):
        super().setUp()
        self.packet = self.create_acct_packet()

    def create_acct_packet(self):
        packet = self.client.create_acct_packet(
            code=PacketType.AccountingRequest, User_Name="wichert"
        )
        packet["NAS-IP-Address"] = "192.168.1.10"
        packet["NAS-Port"] = 0
        packet["Service-Type"] = "Login-User"
        packet["NAS-Identifier"] = "trillian"
        packet["Called-Station-Id"] = "00-04-5F-00-0F-D1"
        packet["Calling-Station-Id"] = "00-01-24-80-B3-9C"
        packet["Framed-IP-Address"] = "10.0.0.100"
        packet["Acct-Status-Type"] = "Start"
        return packet

    async def test_handle_acct_packet(self):
        reply = await self.server.handle_accounting(self.packet)
        self.assertEqual(reply.code, PacketType.AccountingResponse)
