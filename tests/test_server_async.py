import unittest
from unittest.mock import AsyncMock, MagicMock, patch


from pyrad2.constants import PacketType
from pyrad2.server import RemoteHost
from pyrad2.server_async import (
    DatagramProtocolServer,
    ServerAsync,
    ServerType,
)

from .base import DummyServer, capture_logs


class DatagramProtocolServerTests(unittest.TestCase):
    def setUp(self):
        self.server = DummyServer(debug=True)
        self.remote_host = RemoteHost("127.0.0.1", "secret", "name")
        self.hosts = {"127.0.0.1": self.remote_host}
        self.protocol = DatagramProtocolServer(
            ip="127.0.0.1",
            port=1812,
            server=self.server,
            server_type=ServerType.Auth,
            hosts=self.hosts,
            request_callback=self.server._request_handler,
        )
        self.transport = MagicMock()

    def test_connection_made(self):
        with capture_logs() as output:
            self.protocol.connection_made(self.transport)

        self.assertEqual(len(output), 1)
        self.assertEqual(self.protocol.transport, self.transport)

    def test_connection_lost(self):
        with capture_logs() as output:
            self.protocol.connection_lost(None)

        self.assertEqual(len(output), 1)

    def test_error_received(self):
        self.protocol.connection_made(self.transport)
        with capture_logs() as output:
            self.protocol.error_received(Exception("Test error"))

        self.assertEqual(len(output), 1)

    def test_send_response(self):
        self.protocol.connection_made(self.transport)
        mock_packet = MagicMock()
        mock_packet.ReplyPacket.return_value = b"response"
        self.protocol.send_response(mock_packet, ("127.0.0.1", 12345))
        self.transport.sendto.assert_called_once_with(b"response", ("127.0.0.1", 12345))


class ServerAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = DummyServer()
        self.server.dict = MagicMock()
        self.remote_host = RemoteHost("127.0.0.1", "secret", "name")
        self.server.hosts = {"127.0.0.1": self.remote_host}

    @patch.object(DummyServer, "_start_transport", new_callable=AsyncMock)
    async def test_initialize_transports(self, mock_start_transport):
        await self.server.initialize_transports(enable_auth=True)
        mock_start_transport.assert_awaited_once()

    @patch("pyrad2.server_async.DatagramProtocolServer")
    async def test_deinitialize_transports(self, mock_protocol_cls):
        mock_proto = AsyncMock()
        self.server.auth_protocols = [mock_proto]
        await self.server.deinitialize_transports()
        mock_proto.close_transport.assert_awaited_once()
        self.assertEqual(self.server.auth_protocols, [])

    def test_create_reply_packet(self):
        pkt = MagicMock()
        ServerAsync.create_reply_packet(pkt, Attr1="value")
        pkt.CreateReply.assert_called_once_with(Attr1="value")

    def test_request_handler_auth(self):
        mock_pkt = MagicMock(code=PacketType.AccessRequest)
        proto = MagicMock(server_type=ServerType.Auth, ip="127.0.0.1", port=1812)
        self.server._request_handler(proto, mock_pkt, "127.0.0.1")
        self.assertTrue(self.server.auth_called)

    def test_request_handler_acct(self):
        mock_pkt = MagicMock(code=PacketType.AccountingRequest)
        proto = MagicMock(server_type=ServerType.Acct)
        self.server._request_handler(proto, mock_pkt, "127.0.0.1")
        self.assertTrue(self.server.acct_called)

    def test_request_handler_coa(self):
        mock_pkt = MagicMock(code=PacketType.CoARequest)
        proto = MagicMock(server_type=ServerType.Coa)
        self.server._request_handler(proto, mock_pkt, "127.0.0.1")
        self.assertTrue(self.server.coa_called)

    def test_request_handler_disconnect(self):
        mock_pkt = MagicMock(code=PacketType.DisconnectRequest)
        proto = MagicMock(server_type=ServerType.Coa)
        self.server._request_handler(proto, mock_pkt, "127.0.0.1")
        self.assertTrue(self.server.disconnect_called)
