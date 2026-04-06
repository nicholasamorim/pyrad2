import select
import socket
import unittest
from .mock import MockFd
from .mock import MockPoll
from .mock import MockSocket
from .mock import MockClassMethod
from .mock import UnmockClassMethods
from pyrad2.proxy import Proxy
from pyrad2.constants import PacketType
from pyrad2.server import ServerPacketError
from pyrad2.server import Server


class TrivialObject:
    """dummy object"""


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.orgsocket = socket.socket
        socket.socket = MockSocket
        self.proxy = Proxy()
        self.proxy._fdmap = {}

    def tearDown(self):
        socket.socket = self.orgsocket

    def test_proxy_fd(self):
        self.proxy._poll = MockPoll()
        self.proxy._prepare_sockets()
        self.assertTrue(isinstance(self.proxy._proxyfd, MockSocket))
        self.assertEqual(list(self.proxy._fdmap.keys()), [1])
        self.assertEqual(
            self.proxy._poll.registry,
            {1: select.POLLIN | select.POLLPRI | select.POLLERR},
        )


class ProxyPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.proxy = Proxy()
        self.proxy.hosts["host"] = TrivialObject()
        self.proxy.hosts["host"].secret = "supersecret"
        self.packet = TrivialObject()
        self.packet.code = PacketType.AccessAccept
        self.packet.source = ("host", "port")

    def test_handle_proxy_packet_unknownHost(self):
        self.packet.source = ("stranger", "port")
        try:
            self.proxy._handle_proxy_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("unknown host" in str(e))
        else:
            self.fail()

    def test_handle_proxy_packet_sets_secret(self):
        self.proxy._handle_proxy_packet(self.packet)
        self.assertEqual(self.packet.secret, "supersecret")

    def testHandleProxyPacketHandlesWrongPacket(self):
        self.packet.code = PacketType.AccessRequest
        try:
            self.proxy._handle_proxy_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("non-response" in str(e))
        else:
            self.fail()


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.proxy = Proxy()
        self.proxy._proxyfd = MockFd()

    def tearDown(self):
        UnmockClassMethods(Proxy)
        UnmockClassMethods(Server)

    def testProcessInputNonProxyPort(self):
        fd = MockFd(fd=111)
        MockClassMethod(Server, "_process_input")
        self.proxy._process_input(fd)
        self.assertEqual(self.proxy.called, [("_process_input", (fd,), {})])

    def testProcessInput(self):
        MockClassMethod(Proxy, "_grab_packet")
        MockClassMethod(Proxy, "_handle_proxy_packet")
        self.proxy._process_input(self.proxy._proxyfd)
        self.assertEqual(
            [x[0] for x in self.proxy.called], ["_grab_packet", "_handle_proxy_packet"]
        )


if not hasattr(select, "poll"):
    del SocketTests
