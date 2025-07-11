import select
import socket
import unittest
from .mock import MockPacket
from .mock import MockPoll
from .mock import MockSocket
from pyrad2.client import Client
from pyrad2.client import Timeout
from pyrad2.packet import AuthPacket
from pyrad2.packet import AcctPacket
from pyrad2.constants import PacketType

BIND_IP = "127.0.0.1"
BIND_PORT = 53535


class ConstructionTests(unittest.TestCase):
    def setUp(self):
        self.server = object()

    def testSimpleConstruction(self):
        client = Client(self.server)
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 1812)
        self.assertEqual(client.acctport, 1813)
        self.assertEqual(client.secret, b"")
        self.assertEqual(client.retries, 3)
        self.assertEqual(client.timeout, 5)
        self.assertTrue(client.dict is None)

    def testParameterOrder(self):
        marker = object()
        client = Client(self.server, 123, 456, 789, "secret", marker)
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 123)
        self.assertEqual(client.acctport, 456)
        self.assertEqual(client.coaport, 789)
        self.assertEqual(client.secret, "secret")
        self.assertTrue(client.dict is marker)

    def testNamedParameters(self):
        marker = object()
        client = Client(
            server=self.server, authport=123, acctport=456, secret="secret", dict=marker
        )
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 123)
        self.assertEqual(client.acctport, 456)
        self.assertEqual(client.secret, "secret")
        self.assertTrue(client.dict is marker)


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.server = object()
        self.client = Client(self.server)
        self.orgsocket = socket.socket
        socket.socket = MockSocket

    def tearDown(self):
        socket.socket = self.orgsocket

    def testReopen(self):
        self.client._SocketOpen()
        sock = self.client._socket
        self.client._SocketOpen()
        self.assertTrue(sock is self.client._socket)

    def testBind(self):
        self.client.bind((BIND_IP, BIND_PORT))
        self.assertEqual(self.client._socket.address, (BIND_IP, BIND_PORT))
        self.assertEqual(
            self.client._socket.options, [(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)]
        )

    def testBindClosesSocket(self):
        s = MockSocket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client._socket = s
        self.client._poll = MockPoll()
        self.client.bind((BIND_IP, BIND_PORT))
        self.assertEqual(s.closed, True)

    def testSendPacket(self):
        def MockSend(self, pkt, port):
            self._mock_pkt = pkt
            self._mock_port = port

        _SendPacket = Client._SendPacket
        Client._SendPacket = MockSend

        self.client.SendPacket(AuthPacket())
        self.assertEqual(self.client._mock_port, self.client.authport)

        self.client.SendPacket(AcctPacket())
        self.assertEqual(self.client._mock_port, self.client.acctport)

        Client._SendPacket = _SendPacket

    def testNoRetries(self):
        self.client.retries = 0
        self.assertRaises(Timeout, self.client._SendPacket, None, None)

    def testSingleRetry(self):
        self.client.retries = 1
        self.client.timeout = 0
        packet = MockPacket(PacketType.AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(
            self.client._socket.output, [("request packet", (self.server, 432))]
        )

    def testDoubleRetry(self):
        self.client.retries = 2
        self.client.timeout = 0
        packet = MockPacket(PacketType.AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(
            self.client._socket.output,
            [
                ("request packet", (self.server, 432)),
                ("request packet", (self.server, 432)),
            ],
        )

    def testAuthDelay(self):
        self.client.retries = 2
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        packet = MockPacket(PacketType.AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertFalse("Acct-Delay-Time" in packet)

    def testSingleAccountDelay(self):
        self.client.retries = 2
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        packet = MockPacket(PacketType.AccountingRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(packet["Acct-Delay-Time"], [1])

    def testDoubleAccountDelay(self):
        self.client.retries = 3
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        packet = MockPacket(PacketType.AccountingRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(packet["Acct-Delay-Time"], [2])

    def testIgnorePacketError(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        packet = MockPacket(PacketType.AccountingRequest, verify=True, error=True)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)

    def testValidReply(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        self.client._poll = MockPoll()
        MockPoll.results = [(1, select.POLLIN)]
        packet = MockPacket(PacketType.AccountingRequest, verify=True)
        reply = self.client._SendPacket(packet, 432)
        self.assertTrue(reply is packet.reply)

    def testInvalidReply(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"invalid reply")
        MockPoll.results = [(1, select.POLLIN)]
        packet = MockPacket(PacketType.AccountingRequest, verify=False)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.server = object()
        self.client = Client(self.server, secret=b"zeer geheim")

    def testCreateAuthPacket(self):
        packet = self.client.CreateAuthPacket(id=15)
        self.assertTrue(isinstance(packet, AuthPacket))
        self.assertTrue(packet.dict is self.client.dict)
        self.assertEqual(packet.id, 15)
        self.assertEqual(packet.secret, b"zeer geheim")

    def testCreateAcctPacket(self):
        packet = self.client.CreateAcctPacket(id=15)
        self.assertTrue(isinstance(packet, AcctPacket))
        self.assertTrue(packet.dict is self.client.dict)
        self.assertEqual(packet.id, 15)
        self.assertEqual(packet.secret, b"zeer geheim")
