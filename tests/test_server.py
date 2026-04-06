import select
import socket
import unittest
from .mock import MockFinished
from .mock import MockFd
from .mock import MockPoll
from .mock import MockSocket
from .mock import MockClassMethod
from .mock import UnmockClassMethods
from pyrad2.packet import PacketError
from pyrad2.server import RemoteHost
from pyrad2.server import Server
from pyrad2.server import ServerPacketError
from pyrad2.constants import PacketType


class TrivialObject:
    """dummy objec"""

    pass


class RemoteHostTests(unittest.TestCase):
    def testSimpleConstruction(self):
        host = RemoteHost(
            "address", "secret", "name", "authport", "acctport", "coaport"
        )
        self.assertEqual(host.address, "address")
        self.assertEqual(host.secret, "secret")
        self.assertEqual(host.name, "name")
        self.assertEqual(host.authport, "authport")
        self.assertEqual(host.acctport, "acctport")
        self.assertEqual(host.coaport, "coaport")

    def testNamedConstruction(self):
        host = RemoteHost(
            address="address",
            secret="secret",
            name="name",
            authport="authport",
            acctport="acctport",
            coaport="coaport",
        )
        self.assertEqual(host.address, "address")
        self.assertEqual(host.secret, "secret")
        self.assertEqual(host.name, "name")
        self.assertEqual(host.authport, "authport")
        self.assertEqual(host.acctport, "acctport")
        self.assertEqual(host.coaport, "coaport")


class ServerConstructiontests(unittest.TestCase):
    def testSimpleConstruction(self):
        server = Server()
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, 1812)
        self.assertEqual(server.acctport, 1813)
        self.assertEqual(server.coaport, 3799)
        self.assertEqual(server.hosts, {})

    def testParameterOrder(self):
        server = Server([], "authport", "acctport", "coaport", "hosts", "dict")
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, "authport")
        self.assertEqual(server.acctport, "acctport")
        self.assertEqual(server.coaport, "coaport")
        self.assertEqual(server.dict, "dict")

    def testBindDuringConstruction(self):
        def bind_to_address(self, addr):
            self.bound.append(addr)

        bta = Server.bind_to_address
        Server.bind_to_address = bind_to_address

        Server.bound = []
        server = Server(["one", "two", "three"])
        self.assertEqual(server.bound, ["one", "two", "three"])
        del Server.bound

        Server.bind_to_address = bta


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.orgsocket = socket.socket
        socket.socket = MockSocket
        self.server = Server()

    def tearDown(self):
        socket.socket = self.orgsocket

    def testBind(self):
        self.server.bind_to_address("192.168.13.13")
        self.assertEqual(len(self.server.authfds), 1)
        self.assertEqual(self.server.authfds[0].address, ("192.168.13.13", 1812))

        self.assertEqual(len(self.server.acctfds), 1)
        self.assertEqual(self.server.acctfds[0].address, ("192.168.13.13", 1813))

    def testBindv6(self):
        self.server.bind_to_address("2001:db8:123::1")
        self.assertEqual(len(self.server.authfds), 1)
        self.assertEqual(self.server.authfds[0].address, ("2001:db8:123::1", 1812))

        self.assertEqual(len(self.server.acctfds), 1)
        self.assertEqual(self.server.acctfds[0].address, ("2001:db8:123::1", 1813))

    def testgrab_packet(self):
        def gen(data):
            res = TrivialObject()
            res.data = data
            return res

        fd = MockFd()
        fd.source = object()
        pkt = self.server._grab_packet(gen, fd)
        self.assertTrue(isinstance(pkt, TrivialObject))
        self.assertTrue(pkt.fd is fd)
        self.assertTrue(pkt.source is fd.source)
        self.assertTrue(pkt.data is fd.data)

    def testPrepareSocketNoFds(self):
        self.server._poll = MockPoll()
        self.server._prepare_sockets()

        self.assertEqual(self.server._poll.registry, {})
        self.assertEqual(self.server._realauthfds, [])
        self.assertEqual(self.server._realacctfds, [])

    def testPrepareSocketAuthFds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.authfds = [MockFd(12), MockFd(14)]
        self.server._prepare_sockets()

        self.assertEqual(list(self.server._fdmap.keys()), [12, 14])
        self.assertEqual(
            self.server._poll.registry,
            {
                12: select.POLLIN | select.POLLPRI | select.POLLERR,
                14: select.POLLIN | select.POLLPRI | select.POLLERR,
            },
        )

    def testPrepareSocketAcctFds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.acctfds = [MockFd(12), MockFd(14)]
        self.server._prepare_sockets()

        self.assertEqual(list(self.server._fdmap.keys()), [12, 14])
        self.assertEqual(
            self.server._poll.registry,
            {
                12: select.POLLIN | select.POLLPRI | select.POLLERR,
                14: select.POLLIN | select.POLLPRI | select.POLLERR,
            },
        )


class AuthPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.server.hosts["host"] = TrivialObject()
        self.server.hosts["host"].secret = "supersecret"
        self.packet = TrivialObject()
        self.packet.code = PacketType.AccessRequest
        self.packet.source = ("host", "port")

    def testHandleAuthPacketUnknownHost(self):
        self.packet.source = ("stranger", "port")
        try:
            self.server._handle_auth_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("unknown host" in str(e))
        else:
            self.fail()

    def testHandleAuthPacketWrongPort(self):
        self.packet.code = PacketType.AccountingRequest
        try:
            self.server._handle_auth_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("port" in str(e))
        else:
            self.fail()

    def testHandleAuthPacket(self):
        def handle_auth_packet(self, pkt):
            self.handled = pkt

        hap = Server.handle_auth_packet
        Server.handle_auth_packet = handle_auth_packet

        self.server._handle_auth_packet(self.packet)
        self.assertTrue(self.server.handled is self.packet)

        Server.handle_auth_packet = hap


class AcctPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.server.hosts["host"] = TrivialObject()
        self.server.hosts["host"].secret = "supersecret"
        self.packet = TrivialObject()
        self.packet.code = PacketType.AccountingRequest
        self.packet.source = ("host", "port")

    def testHandleAcctPacketUnknownHost(self):
        self.packet.source = ("stranger", "port")
        try:
            self.server._handle_acct_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("unknown host" in str(e))
        else:
            self.fail()

    def testHandleAcctPacketWrongPort(self):
        self.packet.code = PacketType.AccessRequest
        try:
            self.server._handle_acct_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("port" in str(e))
        else:
            self.fail()

    def testHandleAcctPacket(self):
        def handle_acct_packet(self, pkt):
            self.handled = pkt

        hap = Server.handle_acct_packet
        Server.handle_acct_packet = handle_acct_packet

        self.server._handle_acct_packet(self.packet)
        self.assertTrue(self.server.handled is self.packet)

        Server.handle_acct_packet = hap


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()

    def tearDown(self):
        UnmockClassMethods(Server)

    def testcreate_reply_packet(self):
        class TrivialPacket:
            source = object()

            def create_reply(self, **kw):
                reply = TrivialObject()
                reply.kw = kw
                return reply

        reply = self.server.create_reply_packet(TrivialPacket(), one="one", two="two")
        self.assertTrue(isinstance(reply, TrivialObject))
        self.assertTrue(reply.source is TrivialPacket.source)
        self.assertEqual(reply.kw, dict(one="one", two="two"))

    def testAuthProcessInput(self):
        fd = MockFd(1)
        self.server._realauthfds = [1]
        MockClassMethod(Server, "_grab_packet")
        MockClassMethod(Server, "_handle_auth_packet")

        self.server._process_input(fd)
        self.assertEqual(
            [x[0] for x in self.server.called], ["_grab_packet", "_handle_auth_packet"]
        )
        self.assertEqual(self.server.called[0][1][1], fd)

    def testAcctProcessInput(self):
        fd = MockFd(1)
        self.server._realauthfds = []
        self.server._realacctfds = [1]
        MockClassMethod(Server, "_grab_packet")
        MockClassMethod(Server, "_handle_acct_packet")

        self.server._process_input(fd)
        self.assertEqual(
            [x[0] for x in self.server.called], ["_grab_packet", "_handle_acct_packet"]
        )
        self.assertEqual(self.server.called[0][1][1], fd)


class ServerRunTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.origpoll = select.poll
        select.poll = MockPoll

    def tearDown(self):
        MockPoll.results = []
        select.poll = self.origpoll
        UnmockClassMethods(Server)

    def testRunInitializes(self):
        MockClassMethod(Server, "_prepare_sockets")
        self.assertRaises(MockFinished, self.server.run)
        self.assertEqual(self.server.called, [("_prepare_sockets", (), {})])
        self.assertTrue(isinstance(self.server._fdmap, dict))
        self.assertTrue(isinstance(self.server._poll, MockPoll))

    def testRunIgnoresPollErrors(self):
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLERR)]
        self.assertRaises(MockFinished, self.server.run)

    def testRunIgnoresServerPacketErrors(self):
        def RaisePacketError(self, fd):
            raise ServerPacketError

        MockClassMethod(Server, "_process_input", RaisePacketError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.run)

    def testRunIgnoresPacketErrors(self):
        def RaisePacketError(self, fd):
            raise PacketError

        MockClassMethod(Server, "_process_input", RaisePacketError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.run)

    def testRunRunsProcessInput(self):
        MockClassMethod(Server, "_process_input")
        self.server.authfds = fd = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.run)
        self.assertEqual(self.server.called, [("_process_input", (fd[0],), {})])


if not hasattr(select, "poll"):
    del SocketTests
    del ServerRunTests
