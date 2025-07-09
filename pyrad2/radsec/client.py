import asyncio
import ssl
import struct
from hashlib import md5
from typing import Optional

from loguru import logger

from pyrad2.constants import EAPPacketType, EAPType, PacketType
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    CurrentID,
    Packet,
    PacketError,
    PacketImplementation,
)
from pyrad2.tools import read_radius_packet


class RadSecClient:
    def __init__(
        self,
        server: str = "127.0.0.1",
        port: int = 2083,
        secret: bytes = b"radsec",
        dict=None,
        retries: int = 3,
        timeout: int = 5,
        certfile: str = "certs/client/client.cert.pem",
        keyfile: str = "certs/client/client.key.pem",
        certfile_server: str = "certs//ca/ca.cert.pem",
        check_hostname: bool = False,
    ):
        """Initializes a RadSec client.

        Args:
            server (str): IP address to connect to.
            port (int): RadSec port, defaults to 2083.
            secret (bytes): Secret. Defaults to radsec as per RFC 6614.
                Different implementations support setting an arbitrary
                shared secret but if you want to stick to the RFC,
                the shared secret must be `radsec`.
            dict (Dictionary): RADIUS dictionary to use.
            certfile (str): Path to client SSL certificate
            keyfile (str): Path to client SSL certificate
            certfile_server (str): Path to server SSL certificate

        """
        self.server = server
        self.port = port
        self.secret = secret
        self.retries = retries
        self.timeout = timeout
        self.dict = dict

        self.setup_ssl(certfile, keyfile, certfile_server, check_hostname)

    def setup_ssl(
        self, certfile: str, keyfile: str, certfile_server: str, check_hostname: bool
    ):
        try:
            self.ssl_ctx = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=certfile_server
            )

            self.ssl_ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except FileNotFoundError as e:
            ssl_paths = ", ".join([certfile, keyfile, certfile_server])
            msg = "One or more SSL files could not be found. Current paths: {}"
            logger.error(msg, ssl_paths)
            raise FileNotFoundError(msg.format(ssl_paths)) from e

        self.ssl_ctx.check_hostname = check_hostname

    def create_auth_packet(self, **kwargs) -> AuthPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            Packet: A new AuthPacket instance
        """
        id = kwargs.pop("id", Packet.CreateID())
        return AuthPacket(
            dict=self.dict,
            id=id,
            secret=self.secret,
            **kwargs,
        )

    def create_acct_packet(self, **kwargs) -> AcctPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            Packet: A new AcctPacket instance
        """
        id = kwargs.pop("id", Packet.CreateID())
        return AcctPacket(
            id=id,
            dict=self.dict,
            secret=self.secret,
            **kwargs,
        )

    def create_coa_packet(self, **kwargs) -> CoAPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            Packet: A new CoA packet instance
        """
        id = kwargs.pop("id", Packet.CreateID())
        return CoAPacket(id=id, dict=self.dict, secret=self.secret, **kwargs)

    def create_packet(self, id, **kwargs) -> Packet:
        return Packet(id=id, dict=self.dict, secret=self.secret, **kwargs)

    async def _send_packet(self, packet: PacketImplementation) -> Optional[Packet]:
        """Send a packet to a RADIUS server.

        Args:
            packet (Packet): The packet to send
        """
        reader, writer = await asyncio.open_connection(
            self.server, self.port, ssl=self.ssl_ctx
        )

        logger.info(
            "Connected to RADSEC server on {}:{}, sending RADIUS packet",
            self.server,
            self.port,
        )

        writer.write(packet.RequestPacket())
        await writer.drain()

        async def close():
            writer.close()
            await writer.wait_closed()

        try:
            response = await read_radius_packet(reader)
        except asyncio.TimeoutError:
            logger.warning("Timeout waiting for server response")
            await close()
            return None

        if not response:
            logger.info("No response received")
            await close()
            return None

        logger.info("Received {} bytes from server", len(response))
        logger.debug("Response: {}", response.hex())

        try:
            reply = packet.CreateReply(packet=response)
            if packet.VerifyReply(reply, response):
                return reply
        except PacketError as e:
            logger.error("Error creating reply {}", e)
            await close()

        return None

    async def send_packet(self, packet: PacketImplementation) -> Optional[Packet]:
        """Send a packet to a RADIUS server.

        Args:
            packet (Packet): The packet to send
        """
        if isinstance(packet, AuthPacket):
            if packet.auth_type == "eap-md5":
                # Creating EAP-Identity
                password = packet[2][0] if 2 in packet else packet[1][0]
                packet[79] = [
                    struct.pack(
                        "!BBHB%ds" % len(password),
                        EAPPacketType.RESPONSE,
                        CurrentID,
                        len(password) + 5,
                        EAPType.IDENTITY,
                        password,
                    )
                ]
            reply = await self._send_packet(packet)
            if (
                reply
                and reply.code == PacketType.AccessChallenge
                and packet.auth_type == "eap-md5"
            ):
                # Got an Access-Challenge
                eap_code, eap_id, eap_size, eap_type, eap_md5 = struct.unpack(
                    "!BBHB%ds" % (len(reply[79][0]) - 5), reply[79][0]
                )
                # Sending back an EAP-Type-MD5-Challenge
                # Thank god for http://www.secdev.org/python/eapy.py
                client_pw = packet[2][0] if 2 in packet else packet[1][0]
                md5_challenge = md5(
                    struct.pack("!B", eap_id) + client_pw + eap_md5[1:]
                ).digest()
                packet[79] = [
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
                packet[24] = reply[24]
                reply = await self._send_packet(packet)
            return reply
        elif isinstance(packet, CoAPacket):
            return await self._send_packet(packet)
        else:
            return await self._send_packet(packet)
