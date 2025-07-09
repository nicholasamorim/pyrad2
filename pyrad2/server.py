import select
import socket
from dataclasses import dataclass
from typing import Callable, Optional

from loguru import logger

from pyrad2 import host, packet
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import ServerPacketError
from pyrad2.constants import PacketType


@dataclass
class RemoteHost:
    """Remote RADIUS capable host we can talk to.

    Args:
        address (str): IP address.
        secret (bytes): RADIUS secret. If connecting to a RadSec server, the secret should be `radsec`.
        name (str): Short name (used for logging only).
        authport (int): Port used for authentication packets.
        acctport (int): Port used for accounting packets.
        coaport (int): Port used for CoA packets.
    """

    address: str
    secret: bytes
    name: str
    authport: int = 1812
    acctport: int = 1813
    coaport: int = 3799


class Server(host.Host):
    """Basic RADIUS server.
    This class implements the basics of a RADIUS server. It takes care
    of the details of receiving and decoding requests; processing of
    the requests should be done by overloading the appropriate methods
    in derived classes.

    Attributes:
        hosts (dict): Hosts who are allowed to talk to us. Dictionary of Host class instances.
        _poll (select.poll): Poll object for network sockets.
        _fdmap (dict): Map of file descriptors to network sockets.
        MaxPacketSize (int): Maximum size of a RADIUS packet. (class variable)
    """

    MaxPacketSize = 8192

    def __init__(
        self,
        addresses: Optional[list[str]] = None,
        authport: int = 1812,
        acctport: int = 1813,
        coaport: int = 3799,
        hosts: Optional[dict] = None,
        dict: Optional[Dictionary] = None,
        auth_enabled: bool = True,
        acct_enabled: bool = True,
        coa_enabled: bool = False,
    ):
        """Initializes a sync server.

        Args:
            addresses (Sequence[str]): IP addresses to listen on.
            authport (int): Port to listen on for authentication packets.
            acctport (int): Port to listen on for accounting packets.
            coaport (int): Port to listen on for CoA packets.
            hosts (dict[str, RemoteHost]): Hosts who we can talk to. A dictionary mapping IP to RemoteHost class instances.
            dict (Dictionary): RADIUS dictionary to use.
            auth_enabled (bool): Enable auth server (default: True).
            acct_enabled (bool): Enable accounting server (default: True).
            coa_enabled (bool): Enable CoA server (default: False).
        """
        super().__init__(authport, acctport, coaport, dict)

        self.hosts = hosts or {}
        self.auth_enabled = auth_enabled
        self.authfds: list[socket.socket] = []
        self.acct_enabled = acct_enabled
        self.acctfds: list = []
        self.coa_enabled = coa_enabled
        self.coafds: list = []

        if addresses:
            for addr in addresses:
                self.BindToAddress(addr)

    def _GetAddrInfo(
        self, addr: str
    ) -> set[tuple[socket.AddressFamily, str | int]] | list:
        """Use getaddrinfo to lookup all addresses for each address.

        Returns a list of tuples or an empty list:
          [(family, address)]

        Args:
            adddr (str): IP address to lookup
        """
        results = set()
        try:
            tmp = socket.getaddrinfo(addr, 80)
        except socket.gaierror:
            return []

        for el in tmp:
            results.add((el[0], el[4][0]))

        return results

    def BindToAddress(self, addr: str) -> None:
        """Add an address to listen on a specific interface.
        String "0.0.0.0" indicates you want to listen on all interfaces.

        Args:
            addr (str): IP address to listen on
        """
        addrFamily = self._GetAddrInfo(addr)
        for family, address in addrFamily:
            if self.auth_enabled:
                authfd = socket.socket(family, socket.SOCK_DGRAM)
                authfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                authfd.bind((address, self.authport))
                self.authfds.append(authfd)

            if self.acct_enabled:
                acctfd = socket.socket(family, socket.SOCK_DGRAM)
                acctfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                acctfd.bind((address, self.acctport))
                self.acctfds.append(acctfd)

            if self.coa_enabled:
                coafd = socket.socket(family, socket.SOCK_DGRAM)
                coafd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                coafd.bind((address, self.coaport))
                self.coafds.append(coafd)

    def HandleAuthPacket(self, pkt: packet.Packet):
        """Authentication packet handler.
        This is an empty function that is called when a valid
        authentication packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            pkt (packet.Packet): Packet to process
        """

    def HandleAcctPacket(self, pkt: packet.Packet):
        """Accounting packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            pkt (packet.Packet): Packet to process
        """

    def HandleCoaPacket(self, pkt: packet.Packet):
        """CoA packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            pkt (packet.Packet): Packet to process
        """

    def HandleDisconnectPacket(self, pkt: packet.Packet):
        """CoA packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            pkt (packet.Packet): Packet to process
        """

    def _AddSecret(self, pkt: packet.Packet) -> None:
        """Add secret to packets received and raise ServerPacketError
        for unknown hosts.

        Args:
            pkt (packet.Packet): Packet to process
        """
        if pkt.source[0] in self.hosts:
            pkt.secret = self.hosts[pkt.source[0]].secret
        elif "0.0.0.0" in self.hosts:
            pkt.secret = self.hosts["0.0.0.0"].secret
        else:
            raise ServerPacketError("Received packet from unknown host")

    def _HandleAuthPacket(self, pkt: packet.Packet) -> None:
        """Process a packet received on the authentication port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        Args:
            pkt (packet.Packet): Packet to process
        """
        self._AddSecret(pkt)
        if pkt.code != PacketType.AccessRequest:
            raise ServerPacketError(
                "Received non-authentication packet on authentication port"
            )
        self.HandleAuthPacket(pkt)

    def _HandleAcctPacket(self, pkt: packet.Packet) -> None:
        """Process a packet received on the accounting port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        Args:
            pkt (packet.Packet): Packet to process
        """
        self._AddSecret(pkt)
        if pkt.code not in [
            PacketType.AccountingRequest,
            PacketType.AccountingResponse,
        ]:
            raise ServerPacketError("Received non-accounting packet on accounting port")
        self.HandleAcctPacket(pkt)

    def _HandleCoaPacket(self, pkt: packet.Packet) -> None:
        """Process a packet received on the coa port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        Args:
            pkt (packet.Packet): Packet to process
        """
        self._AddSecret(pkt)
        if pkt.code == PacketType.CoARequest:
            self.HandleCoaPacket(pkt)
        elif pkt.code == PacketType.DisconnectRequest:
            self.HandleDisconnectPacket(pkt)
        else:
            raise ServerPacketError("Received non-coa packet on coa port")

    def _GrabPacket(self, pktgen: Callable, fd: socket.socket) -> packet.Packet:
        """Read a packet from a network connection.
        This method assumes there is data waiting for to be read.

        Args:
            fd (socket.socket): Socket to read packet from

        Returns:
            packet.Packet: RADIUS packet
        """
        (data, source) = fd.recvfrom(self.MaxPacketSize)
        pkt = pktgen(data)
        pkt.source = source
        pkt.fd = fd
        return pkt

    def _PrepareSockets(self) -> None:
        """Prepare all sockets to receive packets."""
        for fd in self.authfds + self.acctfds + self.coafds:
            self._fdmap[fd.fileno()] = fd
            self._poll.register(
                fd.fileno(), select.POLLIN | select.POLLPRI | select.POLLERR
            )
        if self.auth_enabled:
            self._realauthfds = list(map(lambda x: x.fileno(), self.authfds))
        if self.acct_enabled:
            self._realacctfds = list(map(lambda x: x.fileno(), self.acctfds))
        if self.coa_enabled:
            self._realcoafds = list(map(lambda x: x.fileno(), self.coafds))

    def CreateReplyPacket(self, pkt: packet.Packet, **attributes) -> packet.Packet:
        """Create a reply packet.
        Create a new packet which can be returned as a reply to a received
        packet.

        Args:
            pkt (packet.Packet): Packet to process
        """
        reply = pkt.CreateReply(**attributes)
        reply.source = pkt.source
        return reply

    def _ProcessInput(self, fd: socket.socket) -> None:
        """Process available data.
        If this packet should be dropped instead of processed a
        PacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        This function calls either HandleAuthPacket() or
        HandleAcctPacket() depending on which socket is being
        processed.

        Args:
            fd (socket.socket): Socket to read the packet from
        """
        if self.auth_enabled and fd.fileno() in self._realauthfds:
            pkt = self._GrabPacket(
                lambda data, s=self: s.CreateAuthPacket(packet=data), fd
            )
            self._HandleAuthPacket(pkt)
        elif self.acct_enabled and fd.fileno() in self._realacctfds:
            pkt = self._GrabPacket(
                lambda data, s=self: s.CreateAcctPacket(packet=data), fd
            )
            self._HandleAcctPacket(pkt)
        elif self.coa_enabled:
            pkt = self._GrabPacket(
                lambda data, s=self: s.CreateCoAPacket(packet=data), fd
            )
            self._HandleCoaPacket(pkt)
        else:
            raise ServerPacketError("Received packet for unknown handler")

    def Run(self) -> None:
        """Main loop.
        This method is the main loop for a RADIUS server. It waits
        for packets to arrive via the network and calls other methods
        to process them.
        """
        self._poll = select.poll()
        self._fdmap: dict[int, socket.socket] = {}
        self._PrepareSockets()

        while True:
            for fd, event in self._poll.poll():
                if event == select.POLLIN:
                    try:
                        fdo = self._fdmap[fd]
                        self._ProcessInput(fdo)
                    except ServerPacketError as err:
                        logger.info("Dropping packet: " + str(err))
                    except packet.PacketError as err:
                        logger.info("Received a broken packet: " + str(err))
                else:
                    logger.error("Unexpected event in server main loop")
