import asyncio
import ssl
from abc import abstractmethod
from typing import Iterable, Optional

from loguru import logger

from pyrad2.constants import ErrorCause, PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    Packet,
    PacketError,
    StatusPacket,
    parse_packet,
    prepare_reply_message_authenticator,
)
from pyrad2.server import RemoteHost, ServerPacketError
from pyrad2.tools import (
    cert_fingerprint_matches,
    get_cert_fingerprint,
    normalize_cert_fingerprint,
    read_radius_packet,
)


ERROR_CAUSE_ATTRIBUTE = 101


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

    DEFAULT_MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_2

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
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED,
        minimum_tls_version: ssl.TLSVersion = DEFAULT_MINIMUM_TLS_VERSION,
        ciphers: Optional[str] = None,
        allowed_client_fingerprints: Optional[Iterable[str]] = None,
        connection_read_timeout: Optional[float] = None,
        max_packets_per_connection: Optional[int] = None,
        require_message_authenticator: bool = False,
        require_eap_message_authenticator: bool = True,
        enable_coa: bool = True,
        enable_disconnect: bool = True,
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
            verify_mode (ssl.VerifyMode): Client certificate verification mode.
            minimum_tls_version (ssl.TLSVersion): Lowest TLS version to negotiate.
            ciphers (str): Optional OpenSSL cipher string override.
            allowed_client_fingerprints (Iterable[str]): Optional SHA-256 certificate
                fingerprint allowlist for client certificates.
            connection_read_timeout (float): Optional timeout while waiting for the
                next packet on an established TLS connection.
            max_packets_per_connection (int): Optional packet limit before closing
                an accepted TLS connection.
            require_message_authenticator (bool): Require Message-Authenticator
                on incoming packets.
            require_eap_message_authenticator (bool): Require
                Message-Authenticator on packets containing EAP-Message.
            enable_coa (bool): Dispatch CoA-Request packets to `handle_coa`;
                disabled requests receive CoA-NAK.
            enable_disconnect (bool): Dispatch Disconnect-Request packets to
                `handle_disconnect`; disabled requests receive Disconnect-NAK.
        """
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.hosts = {} if hosts is None else hosts
        self.dict = dictionary
        self.verify_packet = verify_packet
        self.connection_read_timeout = connection_read_timeout
        self.max_packets_per_connection = max_packets_per_connection
        self.require_message_authenticator = require_message_authenticator
        self.require_eap_message_authenticator = require_eap_message_authenticator
        self.enable_coa = enable_coa
        self.enable_disconnect = enable_disconnect
        self.allowed_client_fingerprints = {
            normalize_cert_fingerprint(fingerprint)
            for fingerprint in (allowed_client_fingerprints or [])
        }

        self.setup_ssl(
            certfile, keyfile, ca_certfile, verify_mode, minimum_tls_version, ciphers
        )

    async def run(self):
        server = await asyncio.start_server(
            self._handle_client,
            host=self.listen_address,
            port=self.listen_port,
            ssl=self.ssl_ctx,
        )

        addr = server.sockets[0].getsockname()
        logger.info("RADSEC Server with mutual TLS running on {}", addr)

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

    def setup_ssl(
        self,
        certfile: str,
        keyfile: str,
        ca_certfile: str,
        verify_mode: ssl.VerifyMode,
        minimum_tls_version: ssl.TLSVersion,
        ciphers: Optional[str],
    ):
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            ssl_ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except FileNotFoundError as e:
            ssl_paths = ", ".join([certfile, keyfile, ca_certfile])
            msg = "One or more SSL files could not be found. Current paths: {}"
            logger.error(msg, ssl_paths)
            raise FileNotFoundError(msg.format(ssl_paths)) from e

        ssl_ctx.verify_mode = verify_mode
        ssl_ctx.minimum_version = minimum_tls_version
        ssl_ctx.load_verify_locations(cafile=ca_certfile)
        if ciphers is not None:
            ssl_ctx.set_ciphers(ciphers)

        self.ssl_ctx = ssl_ctx

    def _verify_client_fingerprint(self, cert: bytes | None) -> bool:
        """Verify a client certificate against the fingerprint allowlist.

        If no fingerprints were configured, the certificate trust decision is
        left to Python's TLS verification.
        """
        if not self.allowed_client_fingerprints:
            return True
        if cert is None:
            return False
        return cert_fingerprint_matches(cert, self.allowed_client_fingerprints)

    async def _read_packet(self, reader: asyncio.StreamReader) -> bytes:
        """Read one RADIUS packet from a RadSec stream.

        When `connection_read_timeout` is configured, the read must complete
        within that many seconds.
        """
        if self.connection_read_timeout is None:
            return await read_radius_packet(reader)
        return await asyncio.wait_for(
            read_radius_packet(reader), timeout=self.connection_read_timeout
        )

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter) -> None:
        """Close a stream writer and wait until the close completes."""
        writer.close()
        await writer.wait_closed()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle one accepted RadSec TLS connection.

        The method reads and responds to packets until the peer closes the
        stream, a read timeout/malformed packet occurs, or
        `max_packets_per_connection` is reached.
        """
        peername = writer.get_extra_info("peername")
        cert_bin = writer.get_extra_info("peercert", default=None)

        client_id = None
        if cert_bin:
            client_id = writer.get_extra_info("ssl_object").getpeercert(
                binary_form=True
            )
            logger.info(
                "Client {} fingerprint: {}", peername, get_cert_fingerprint(client_id)
            )
        else:
            logger.warning("No certificate from client {}", peername)

        if not self._verify_client_fingerprint(client_id):
            logger.warning("Client {} certificate fingerprint is not allowed", peername)
            writer.close()
            await writer.wait_closed()
            return

        logger.info("RADSEC connection established from {}", peername)

        packets_processed = 0
        try:
            while True:
                try:
                    data = await self._read_packet(reader)
                except asyncio.IncompleteReadError:
                    logger.info("RADSEC connection closed by {}", peername)
                    return
                except asyncio.TimeoutError:
                    logger.warning("RADSEC connection from {} timed out", peername)
                    return
                except ValueError as exc:
                    logger.warning("Invalid RADSEC packet from {}: {}", peername, exc)
                    return

                logger.info("Received {} bytes from {}", len(data), peername)
                logger.debug("Data (hex): {}", data.hex())

                try:
                    reply = await self.packet_received(data, host=peername[0])
                except UnknownHost:
                    logger.warning("Drop package from unknown source {}", peername[0])
                    return

                writer.write(reply.reply_packet())
                await writer.drain()
                logger.info("Sent reply to {}: {}", peername, reply.code)

                packets_processed += 1
                if (
                    self.max_packets_per_connection is not None
                    and packets_processed >= self.max_packets_per_connection
                ):
                    logger.info(
                        "Closing RADSEC connection from {} after {} packets",
                        peername,
                        packets_processed,
                    )
                    return
        finally:
            await self._close_writer(writer)

    def _verify_packet(self, packet: Packet) -> bool:
        """Verify a parsed request packet using its packet-specific verifier."""
        if isinstance(packet, AuthPacket):
            return packet.verify_auth_request()
        if isinstance(packet, AcctPacket):
            return packet.verify_acct_request()
        if isinstance(packet, CoAPacket):
            return packet.verify_coa_request()
        if isinstance(packet, StatusPacket):
            try:
                return packet.verify_message_authenticator()
            except Exception:
                return False
        return packet.verify_packet()

    def _validate_message_authenticator_policy(self, packet: Packet) -> None:
        """Validate incoming Message-Authenticator policy for a packet."""
        packet.validate_message_authenticator_policy(
            require_message_authenticator=self.require_message_authenticator,
            require_eap_message_authenticator=self.require_eap_message_authenticator,
        )

    def _prepare_reply_packet(self, request: Packet, reply: Packet) -> None:
        """Apply outgoing Message-Authenticator policy to a reply packet."""
        prepare_reply_message_authenticator(
            request,
            reply,
            require_message_authenticator=self.require_message_authenticator,
            require_eap_message_authenticator=self.require_eap_message_authenticator,
        )

    @staticmethod
    def _add_error_cause(reply: Packet, cause: ErrorCause) -> None:
        """Add an RFC 5176 Error-Cause value without requiring dictionary support."""
        reply[ERROR_CAUSE_ATTRIBUTE] = [int(cause).to_bytes(4, "big")]

    def _create_unsupported_coa_reply(self, packet: CoAPacket, code: PacketType) -> Packet:
        """Create a NAK response for unsupported Dynamic Authorization requests."""
        reply = packet.create_reply()
        reply.code = code
        self._add_error_cause(reply, ErrorCause.UnsupportedExtension)
        return reply

    async def packet_received(self, data: bytes, host: str) -> Packet:
        if host in self.hosts:
            remote_host = self.hosts[host]
        elif "0.0.0.0" in self.hosts:
            remote_host = self.hosts["0.0.0.0"]
        else:
            raise UnknownHost

        packet = parse_packet(data, remote_host.secret, self.dict)

        if self.verify_packet:
            if not self._verify_packet(packet):
                raise PacketError("Packet verification failed")

        self._validate_message_authenticator_policy(packet)

        if packet.code == PacketType.StatusServer:
            reply = packet.create_reply(code=PacketType.AccessAccept)
            logger.debug(
                "Received RadSec Status-Server from {}; replying with {}",
                host,
                PacketType(reply.code).name,
            )
        elif packet.code == PacketType.AccessRequest:
            reply = await self.handle_access_request(packet)
        elif packet.code in (
            PacketType.AccountingRequest,
            PacketType.AccountingResponse,
        ):
            reply = await self.handle_accounting(packet)
        elif packet.code == PacketType.CoARequest:
            if self.enable_coa:
                reply = await self.handle_coa(packet)
            else:
                reply = self._create_unsupported_coa_reply(packet, PacketType.CoANAK)
        elif packet.code == PacketType.DisconnectRequest:
            if self.enable_disconnect:
                reply = await self.handle_disconnect(packet)
            else:
                reply = self._create_unsupported_coa_reply(
                    packet, PacketType.DisconnectNAK
                )
        else:
            raise ServerPacketError("Unsupported packet code: {}".format(packet.code))

        self._prepare_reply_packet(packet, reply)
        return reply

    @abstractmethod
    async def handle_access_request(self, packet: AuthPacket) -> Packet:
        """Handle an Access-Request packet."""
        raise NotImplementedError("Subclasses must implement this method")

    @abstractmethod
    async def handle_accounting(self, packet: AcctPacket) -> Packet:
        """Handle an Accounting-Request or Accounting-Response packet."""
        raise NotImplementedError("Subclasses must implement this method")

    async def handle_coa(self, packet: CoAPacket) -> Packet:
        """Handle an unsupported CoA-Request with a CoA-NAK by default.

        Override this method when the RadSec server is acting as a Dynamic
        Authorization Server and can apply authorization changes.
        """
        return self._create_unsupported_coa_reply(packet, PacketType.CoANAK)

    async def handle_disconnect(self, packet: CoAPacket) -> Packet:
        """Handle an unsupported Disconnect-Request with a NAK by default.

        Override this method when the RadSec server is acting as a Dynamic
        Authorization Server and can terminate sessions.
        """
        return self._create_unsupported_coa_reply(packet, PacketType.DisconnectNAK)
