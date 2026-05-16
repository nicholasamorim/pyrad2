import os
import ssl
import unittest

from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.radsec.client import RadSecClient
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer
from pyrad2.radsec.server import UnknownHost
from pyrad2.server import RemoteHost
from pyrad2.tools import get_cert_fingerprint

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
EXAMPLE_ROOT_PATH = os.path.join(os.path.dirname(TEST_ROOT_PATH), "examples")
EXAMPLE_SERVER_CERTFILE = os.path.join(
    EXAMPLE_ROOT_PATH, "certs/server/server.cert.pem"
)


def load_der_cert(path):
    with open(path) as cert_file:
        return ssl.PEM_cert_to_DER_cert(cert_file.read())


def load_cert_fingerprint(path):
    return get_cert_fingerprint(load_der_cert(path))


class FakeSSLObject:
    def __init__(self, cert):
        self.cert = cert

    def getpeercert(self, binary_form=False):
        if binary_form:
            return self.cert
        return {"subject": "test"}


class FakeWriter:
    def __init__(self, cert):
        self.ssl_object = FakeSSLObject(cert)

    def get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self.ssl_object
        return default


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


class ExampleCertificateTests(unittest.TestCase):
    def test_example_server_certificate_matches_local_development_hosts(self):
        cert = ssl._ssl._test_decode_cert(EXAMPLE_SERVER_CERTFILE)
        subject_alt_names = set(cert["subjectAltName"])

        self.assertIn(("DNS", "localhost"), subject_alt_names)
        self.assertIn(("DNS", "radsec-server"), subject_alt_names)
        self.assertIn(("IP Address", "127.0.0.1"), subject_alt_names)
        self.assertIn(("IP Address", "0:0:0:0:0:0:0:1"), subject_alt_names)


class RadSecServer(BaseRadSecServer):
    async def handle_access_request(self, packet):
        reply = packet.create_reply(
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "192.168.0.1",
                "Framed-IPv6-Prefix": "fc66::1/64",
            },
        )

        reply.code = PacketType.AccessAccept
        return reply

    async def handle_accounting(self, packet):
        return packet.create_reply()

    async def handle_disconnect(self, packet):
        reply = packet.create_reply()
        reply.code = 45  # COA NAK
        return reply

    async def handle_coa(self, packet):
        return packet.create_reply()


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
        self.assertEqual(self.server.ssl_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(
            self.server.ssl_ctx.minimum_version,
            BaseRadSecServer.DEFAULT_MINIMUM_TLS_VERSION,
        )

    def test_client_uses_secure_tls_defaults(self):
        self.assertTrue(self.client.ssl_ctx.check_hostname)
        self.assertEqual(self.client.ssl_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(
            self.client.ssl_ctx.minimum_version,
            RadSecClient.DEFAULT_MINIMUM_TLS_VERSION,
        )

    def test_client_can_disable_hostname_validation_explicitly(self):
        client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            check_hostname=False,
        )

        self.assertFalse(client.ssl_ctx.check_hostname)

    def test_server_fingerprint_allowlist_accepts_known_client_certificate(self):
        fingerprint = load_cert_fingerprint(CLIENT_CERTFILE)
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            allowed_client_fingerprints={fingerprint},
        )

        self.assertTrue(
            server._verify_client_fingerprint(load_der_cert(CLIENT_CERTFILE))
        )

    def test_server_fingerprint_allowlist_rejects_unknown_client_certificate(self):
        fingerprint = load_cert_fingerprint(SERVER_CERTFILE)
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            allowed_client_fingerprints={fingerprint},
        )

        self.assertFalse(
            server._verify_client_fingerprint(load_der_cert(CLIENT_CERTFILE))
        )
        self.assertFalse(server._verify_client_fingerprint(None))

    def test_client_fingerprint_allowlist_accepts_known_server_certificate(self):
        fingerprint = load_cert_fingerprint(SERVER_CERTFILE)
        client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            allowed_server_fingerprints={fingerprint},
        )

        self.assertTrue(
            client._verify_server_fingerprint(FakeWriter(load_der_cert(SERVER_CERTFILE)))
        )

    def test_client_fingerprint_allowlist_rejects_unknown_server_certificate(self):
        fingerprint = load_cert_fingerprint(CLIENT_CERTFILE)
        client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            allowed_server_fingerprints={fingerprint},
        )

        self.assertFalse(
            client._verify_server_fingerprint(FakeWriter(load_der_cert(SERVER_CERTFILE)))
        )

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
