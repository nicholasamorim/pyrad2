import asyncio
import ssl
from abc import abstractmethod
from typing import Optional

from loguru import logger

from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    Packet,
    PacketError,
    parse_packet,
)
from pyrad2.server import RemoteHost, ServerPacketError
from pyrad2.tools import get_client_fingerprint, read_radius_packet


class UnknownHost(Exception):
    pass


class RadSecServer:
    """A RadSec as per RFC6614.

    UDP + MD5 has proven to be a combination that has not survived
    the test of time. Hence, the RADIUS standard adopted RADSEC
    as a fundamentally more secure approach.

    RADSEC effectively means performing communications over TCP instead of UDP
    (generally on port 2083) and use TLS as a security layer.

    RADSEC is the same as “Radius Over TLS” or Radius/TLS.

    The default destination port number for RADIUS over TLS is TCP/2083.
    There are no separate ports for authentication, accounting, and
    dynamic authorization changes.
    """

    ALLOWED_CIPHERS = "DES-CBC3-SHA:RC4-SHA:AES128-SHA"

    def __init__(
        self,
        listen_address: str = "0.0.0.0",
        listen_port: int = 2083,
        hosts: Optional[dict[str, RemoteHost]] = None,
        dictionary: Optional[Dictionary] = None,
        verify_packet: bool = False,
        certfile: str = "certs/server/server.cert.pem",
        keyfile: str = "certs/server/server.key.pem",
        ca_certfile: str = "certs/ca/ca.cert.pem",
        verify_mode: ssl.VerifyMode = ssl.CERT_NONE,
    ):
        """Initializes a RadSec server.

        Args:
            listen_address (str): IP address to bind to, defaults to 0.0.0.0
            listen_port (int): Deafaults to 2083.
            hosts (dict[str, RemoteHost]): Hosts who we can talk to. A dictionary mapping IP to RemoteHost class instances.
            dictionary (Dictionary): RADIUS dictionary to use.
            verify_packet (bool): If true, the packet will be verified against its secret
            certfile (str): Path to server SSL certificate
            keyfile (str): Path to server SSL certificate
            ca_certfile (str): Path to server CA certfificate
        """
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.hosts = {} if hosts is None else hosts
        self.dict = dictionary
        self.verify_packet = verify_packet

        self.setup_ssl(certfile, keyfile, ca_certfile, verify_mode)

    async def run(self):
        server = await asyncio.start_server(
            self._handle_client,
            host=self.listen_address,
            port=self.listen_port,
            ssl=self.ssl_ctx,
        )

        addr = server.sockets[0].getsockname()
        logger.info("RADSEC Server with mutual TLS running on {}", addr)
        logger.info("Allowed ciphers: {}", self.ALLOWED_CIPHERS)

        try:
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            logger.info("Task cancelled")
        except KeyboardInterrupt:
            logger.info("Server killed manually")
        finally:
            server.close()
            await server.wait_closed()
            logger.info("Server shutdown")

    def setup_ssl(self, certfile: str, keyfile: str, ca_certfile: str, verify_mode):
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            ssl_ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except FileNotFoundError as e:
            ssl_paths = ", ".join([certfile, keyfile, ca_certfile])
            msg = "One or more SSL files could not be found. Current paths: {}"
            logger.error(msg, ssl_paths)
            raise FileNotFoundError(msg.format(ssl_paths)) from e

        ### NOTE: This must be ssl.CERT_VERIFY but I haven't been able to
        ### to generate proper certificates to make this work.
        ssl_ctx.verify_mode = verify_mode
        ssl_ctx.load_verify_locations(cafile=ca_certfile)
        ssl_ctx.set_ciphers(self.ALLOWED_CIPHERS)

        self.ssl_ctx = ssl_ctx

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")
        cert_bin = writer.get_extra_info("peercert", default=None)

        client_id = None
        if cert_bin:
            cert = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            # fingerprint = hashlib.sha256(cert).hexdigest()
            client_id = get_client_fingerprint(cert)
            logger.info("Client {} fingerprint: {}", peername, client_id)
        else:
            logger.warning("No certificate from client {}", peername)

        logger.info("RADSEC connection established from {}", peername)

        data = await read_radius_packet(reader)
        logger.info("Received {} bytes from {}", len(data), peername)
        logger.debug("Data (hex): {}", data.hex())

        try:
            reply = await self.packet_received(data, host=peername[0])
        except UnknownHost:
            logger.warning("Drop package from unknown source {}", peername[0])
            return

        writer.write(reply.ReplyPacket())
        await writer.drain()
        logger.info("Sent reply to {}: {}", peername, reply.code)

    async def packet_received(self, data: bytes, host: str) -> Packet:
        if host in self.hosts:
            remote_host = self.hosts[host]
        elif "0.0.0.0" in self.hosts:
            remote_host = self.hosts["0.0.0.0"]
        else:
            raise UnknownHost

        packet = parse_packet(data, remote_host.secret, self.dict)

        if self.verify_packet:
            if not packet.verify():
                raise PacketError("Packet verification failed")

        if packet.code == PacketType.AccessRequest:
            return await self.handle_access_request(packet)
        elif packet.code in (
            PacketType.AccountingRequest,
            PacketType.AccountingResponse,
        ):
            return await self.handle_accounting(packet)
        elif packet.code == PacketType.CoARequest:
            return await self.handle_coa(packet)
        elif packet.code == PacketType.DisconnectRequest:
            return await self.handle_disconnect(packet)
        else:
            raise ServerPacketError("Unsupported packet code: {}".format(packet.code))

    @abstractmethod
    async def handle_access_request(self, packet: AuthPacket) -> Packet:
        """Handle an Access-Request packet."""
        raise NotImplementedError("Subclasses must implement this method")

    @abstractmethod
    async def handle_accounting(self, packet: AcctPacket) -> Packet:
        """Handle an Accounting-Request or Accounting-Response packet."""
        raise NotImplementedError("Subclasses must implement this method")

    @abstractmethod
    async def handle_coa(self, packet: CoAPacket) -> Packet:
        """Handle a CoA-Request packet."""
        raise NotImplementedError("Subclasses must implement this method")

    @abstractmethod
    async def handle_disconnect(self, packet: CoAPacket) -> Packet:
        """Handle a Disconnect-Request packet."""
        raise NotImplementedError("Subclasses must implement this method")
