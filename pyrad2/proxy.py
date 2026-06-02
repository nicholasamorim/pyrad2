# proxy.py
#
# Copyright 2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS proxy as defined in RFC 2138

import os

if os.name == "nt":
    import selectors
else:
    import select
import socket

from pyrad2 import packet
from pyrad2.constants import PacketType
from pyrad2.server import Server, ServerPacketError


class Proxy(Server):
    """Base class for RADIUS proxies.

    Extends :obj:`pyrad2.server.Server` with a second UDP socket
    (``_proxyfd``) used to talk to upstream RADIUS servers. The standard
    auth/acct/coa listeners receive client requests; replies from
    upstream RADIUS servers arrive back on ``_proxyfd`` and are
    dispatched to ``_handle_proxy_packet`` for forwarding to the
    original requester.

    Subclasses typically override ``handle_auth_packet`` /
    ``handle_acct_packet`` to forward inbound requests on ``_proxyfd``
    and ``_handle_proxy_packet`` to match the upstream reply back to
    the original client.

    Attributes:
        _proxyfd (socket.socket): UDP socket used to communicate with
            upstream RADIUS servers.
    """

    def _prepare_sockets(self):
        super()._prepare_sockets()
        self._proxyfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._fdmap[self._proxyfd.fileno()] = self._proxyfd
        if os.name == "nt":
            self._sel.register(self._proxyfd.fileno(), selectors.EVENT_READ)
        else:
            self._poll.register(
                self._proxyfd.fileno(),
                (select.POLLIN | select.POLLPRI | select.POLLERR),
            )

    def _handle_proxy_packet(self, pkt: packet.Packet) -> None:
        """Process a packet received on the upstream-reply socket.

        Raises :obj:`pyrad2.exceptions.ServerPacketError` if the packet
        should be dropped (unknown source, or a code that isn't a
        legitimate reply from an upstream RADIUS server). The main loop
        catches the exception and logs the reason; subclasses typically
        override this method to forward the validated reply back to the
        original client.

        The upstream RADIUS server's address must appear in ``self.hosts``
        for the same reason a NAS does — the proxy needs the shared
        secret to verify the upstream response. ``_grab_packet`` does
        the host lookup and seeds ``pkt.secret`` during parse; this
        method's own ``hosts`` check guards callers that construct
        ``pkt`` by hand (e.g. unit tests).

        Args:
            pkt (packet.Packet): Reply packet from an upstream RADIUS
                server.
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

    def _process_input(self, fd: socket.socket) -> None:
        """Dispatch an incoming UDP datagram.

        If the datagram landed on ``_proxyfd`` it's an upstream reply and
        flows through ``_handle_proxy_packet``. Anything else is a
        client-side request and flows through the base server's
        per-port handlers.
        """
        if fd.fileno() == self._proxyfd.fileno():
            # The upstream RADIUS server must be registered as a host
            # (same as a NAS) so ``_grab_packet`` can resolve its shared
            # secret. ``ServerPacketError("Received packet from unknown
            # host")`` is raised otherwise — the main loop catches and
            # logs, exactly like the auth-port path.
            pkt = self._grab_packet(fd)
            self._handle_proxy_packet(pkt)
        else:
            Server._process_input(self, fd)
