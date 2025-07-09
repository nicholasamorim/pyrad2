# proxy.py
#
# Copyright 2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS proxy as defined in RFC 2138

import select
import socket

from pyrad2 import packet
from pyrad2.constants import PacketType
from pyrad2.server import Server, ServerPacketError


class Proxy(Server):
    """Base class for RADIUS proxies.
    This class extends tha RADIUS server class with the capability to
    handle communication with other RADIUS servers as well.

    Attributes:
        _proxyfd (socket.socket): network socket used to communicate with other servers
    """

    def _PrepareSockets(self):
        super()._PrepareSockets()
        self._proxyfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._fdmap[self._proxyfd.fileno()] = self._proxyfd
        self._poll.register(
            self._proxyfd.fileno(), (select.POLLIN | select.POLLPRI | select.POLLERR)
        )

    def _HandleProxyPacket(self, pkt: packet.Packet) -> None:
        """Process a packet received on the reply socket.
        If this packet should be dropped instead of processed a
        :obj:`ServerPacketError` exception should be raised. The main loop
        will drop the packet and log the reason.

        Args:
            pkt (packet.Packet): Packet to process
        """
        if pkt.source[0] not in self.hosts:
            raise ServerPacketError("Received packet from unknown host")
        pkt.secret = self.hosts[pkt.source[0]].secret

        if pkt.code not in [
            PacketType.AccessAccept,
            PacketType.AccessReject,
            PacketType.AccountingResponse,
        ]:
            raise ServerPacketError("Received non-response on proxy socket")

    def _ProcessInput(self, fd: socket.socket) -> None:
        """Process available data.
        If this packet should be dropped instead of processed a
        `ServerPacketError` exception should be raised. The main loop
        will drop the packet and log the reason.

        This function calls either :obj:`HandleAuthPacket`,
        :obj:`HandleAcctPacket` or :obj:`_HandleProxyPacket` depending on
        which socket is being processed.

        Args:
            fd (socket.socket): socket to read packet from
        """
        if fd.fileno() == self._proxyfd.fileno():
            pkt = self._GrabPacket(lambda data, s=self: s.CreatePacket(packet=data), fd)
            self._HandleProxyPacket(pkt)
        else:
            Server._ProcessInput(self, fd)
