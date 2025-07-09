import hashlib
import select
import socket
import struct
import time
from typing import Optional

from pyrad2 import host, packet
from pyrad2.constants import PacketType, EAPPacketType, EAPType
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import Timeout


class Client(host.Host):
    """Basic RADIUS client.
    This class implements a basic RADIUS client. It can send requests
    to a RADIUS server, taking care of timeouts and retries, and
    validate its replies.
    """

    def __init__(
        self,
        server: str,
        authport: int = 1812,
        acctport: int = 1813,
        coaport: int = 3799,
        secret: bytes = b"",
        dict: Optional[Dictionary] = None,
        retries: int = 3,
        timeout: int = 5,
    ):
        """Initializes a RADIUS client.

        Args:
            server (str): Hostname or IP address of the RADIUS server.
            authport (int): Port to use for authentication packets.
            acctport (int): Port to use for accounting packets.
            coaport (int): Port to use for CoA packets.
            secret (bytes): RADIUS secret.
            dict (pyrad.dictionary.Dictionary): RADIUS dictionary.
            retries (int): Number of times to retry sending a RADIUS request.
            timeout (int): Number of seconds to wait for an answer.
        """
        super().__init__(authport, acctport, coaport, dict)

        self.server = server
        self.secret = secret
        self.retries = retries
        self.timeout = timeout
        self._poll = select.poll()
        self._socket: Optional[socket.socket] = None

    def bind(self, addr: str | tuple) -> None:
        """Bind socket to an address.
        Binding the socket used for communicating to an address can be
        usefull when working on a machine with multiple addresses.

        Args:
            addr (str | tuple): network address (hostname or IP) and port to bind to
        """
        self._CloseSocket()
        self._SocketOpen()
        if self._socket:
            self._socket.bind(addr)
        else:
            raise RuntimeError("No socket present")

    def _SocketOpen(self) -> None:
        try:
            family = socket.getaddrinfo(self.server, 80)[0][0]
        except Exception:
            family = socket.AF_INET
        if not self._socket:
            self._socket = socket.socket(family, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._poll.register(self._socket, select.POLLIN)

    def _CloseSocket(self) -> None:
        if self._socket:
            self._poll.unregister(self._socket)
            self._socket.close()
            self._socket = None

    def CreateAuthPacket(self, **args) -> packet.Packet:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """
        return super().CreateAuthPacket(secret=self.secret, **args)

    def CreateAcctPacket(self, **args) -> packet.Packet:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """
        return super().CreateAcctPacket(secret=self.secret, **args)

    def CreateCoAPacket(self, **args) -> packet.Packet:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """
        return super().CreateCoAPacket(secret=self.secret, **args)

    def _SendPacket(self, pkt: packet.PacketImplementation, port: int):
        """Send a packet to a RADIUS server.

        Args:
            pkt (packet.Packet): The packet to send
            port (int): UDP port to send packet to

        Returns:
            packet.Packet: The reply packet received

        Raises:
            Timeout: RADIUS server does not reply
        """
        self._SocketOpen()

        for attempt in range(self.retries):
            if attempt and pkt.code == PacketType.AccountingRequest:
                if "Acct-Delay-Time" in pkt:
                    pkt["Acct-Delay-Time"] = pkt["Acct-Delay-Time"][0] + self.timeout
                else:
                    pkt["Acct-Delay-Time"] = self.timeout

            now = time.time()
            waitto = now + self.timeout

            if not self._socket:
                raise RuntimeError("No socket present")

            self._socket.sendto(pkt.RequestPacket(), (self.server, port))

            while now < waitto:
                ready = self._poll.poll((waitto - now) * 1000)

                if ready:
                    rawreply = self._socket.recv(4096)
                else:
                    now = time.time()
                    continue

                try:
                    reply = pkt.CreateReply(packet=rawreply)
                    if pkt.VerifyReply(reply, rawreply):
                        return reply
                except packet.PacketError:
                    pass

                now = time.time()

        raise Timeout

    def SendPacket(self, pkt: packet.PacketImplementation) -> packet.Packet:  # type: ignore
        """Send a packet to a RADIUS server.

        Args:
            pkt (packet.Packet): Packet to send

        Returns:
            packet.Packet: The reply packet received

        Raises:
            Timeout: RADIUS server does not reply
        """
        if isinstance(pkt, packet.AuthPacket):
            if pkt.auth_type == "eap-md5":
                # Creating EAP-Identity
                password = pkt[2][0] if 2 in pkt else pkt[1][0]
                pkt[79] = [
                    struct.pack(
                        "!BBHB%ds" % len(password),
                        EAPPacketType.RESPONSE,
                        packet.CurrentID,
                        len(password) + 5,
                        EAPType.IDENTITY,
                        password,
                    )
                ]
            reply = self._SendPacket(pkt, self.authport)
            if (
                reply
                and reply.code == PacketType.AccessChallenge
                and pkt.auth_type == "eap-md5"
            ):
                # Got an Access-Challenge
                eap_code, eap_id, eap_size, eap_type, eap_md5 = struct.unpack(
                    "!BBHB%ds" % (len(reply[79][0]) - 5), reply[79][0]
                )
                # Sending back an EAP-Type-MD5-Challenge
                # Thank god for http://www.secdev.org/python/eapy.py
                client_pw = pkt[2][0] if 2 in pkt else pkt[1][0]
                md5_challenge = hashlib.md5(
                    struct.pack("!B", eap_id) + client_pw + eap_md5[1:]
                ).digest()
                pkt[79] = [
                    struct.pack(
                        "!BBHBB",
                        2,
                        eap_id,
                        len(md5_challenge) + 6,
                        4,
                        len(md5_challenge),
                    )
                    + md5_challenge
                ]
                # Copy over Challenge-State
                pkt[24] = reply[24]
                reply = self._SendPacket(pkt, self.authport)
            return reply
        elif isinstance(pkt, packet.CoAPacket):
            return self._SendPacket(pkt, self.coaport)
        else:
            return self._SendPacket(pkt, self.acctport)
