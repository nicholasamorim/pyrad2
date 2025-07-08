import asyncio
import ssl
import struct
from hashlib import md5

from loguru import logger

from pyrad2.packet import (
    EAP_CODE_RESPONSE,
    EAP_TYPE_IDENTITY,
    AccessChallenge,
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
        certfile: str = "certs/client/client.crt",
        keyfile: str = "certs/client/client.key",
        certfile_server: str = "certs/server/server.crt",
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

        self.ssl_ctx = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=certfile_server
        )
        self.ssl_ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.ssl_ctx.check_hostname = False

    def create_auth_packet(self, **kwargs) -> AuthPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            Packet: A new AuthPacket instance
        """
        id = kwargs.pop("id", Packet.create_id())
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
        id = kwargs.pop("id", Packet.create_id())
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
        id = kwargs.pop("id", Packet.create_id())
        return CoAPacket(id=id, dict=self.dict, secret=self.secret, **kwargs)

    def create_packet(self, id, **kwargs) -> Packet:
        return Packet(id=id, dict=self.dict, secret=self.secret, **kwargs)

    async def _send_packet(self, packet: PacketImplementation) -> None:
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

        writer.write(packet.request_packet())
        await writer.drain()

        try:
            response = await read_radius_packet(reader)
            if response:
                logger.info("Received {} bytes from server", len(response))
                logger.debug("Response: {}", response.hex())

                try:
                    reply = packet.create_reply(packet=response)
                    if packet.verify_reply(reply, response):
                        return reply
                except PacketError as e:
                    logger.error("Error creating reply {}", e)
                    pass

            else:
                logger.info("No response received")
        except asyncio.TimeoutError:
            logger.warning("Timeout waiting for server response")

        writer.close()
        await writer.wait_closed()

    async def send_packet(self, packet: PacketImplementation) -> None:
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
                        EAP_CODE_RESPONSE,
                        CurrentID,
                        len(password) + 5,
                        EAP_TYPE_IDENTITY,
                        password,
                    )
                ]
            reply = await self._send_packet(packet)
            if (
                reply
                and reply.code == AccessChallenge
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
            await self._send_packet(packet)
        else:
            await self._send_packet(packet)
