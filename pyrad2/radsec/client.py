import asyncio
import ssl
import struct
from hashlib import md5
from typing import Iterable, Optional

from loguru import logger

from pyrad2.constants import EAPPacketType, EAPType, PacketType
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    CURRENT_ID,
    Packet,
    PacketError,
    PacketImplementation,
    prepare_request_message_authenticator,
)
from pyrad2.tools import read_radius_packet
from pyrad2.tools import cert_fingerprint_matches, normalize_cert_fingerprint


class RadSecClient:
    DEFAULT_MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_2

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
        check_hostname: bool = True,
        minimum_tls_version: ssl.TLSVersion = DEFAULT_MINIMUM_TLS_VERSION,
        ciphers: Optional[str] = None,
        allowed_server_fingerprints: Optional[Iterable[str]] = None,
        reuse_connection: bool = True,
        reconnect_backoff: float = 0.25,
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
            check_hostname (bool): Validate the server certificate name.
            minimum_tls_version (ssl.TLSVersion): Lowest TLS version to negotiate.
            ciphers (str): Optional OpenSSL cipher string override.
            allowed_server_fingerprints (Iterable[str]): Optional SHA-256 certificate
                fingerprint allowlist for the server certificate.
            reuse_connection (bool): Reuse the TLS connection for multiple packets.
            reconnect_backoff (float): Seconds to wait before retrying after a
                connection or read failure.

        """
        self.server = server
        self.port = port
        self.secret = secret
        self.retries = retries
        self.timeout = timeout
        self.dict = dict
        self.reuse_connection = reuse_connection
        self.reconnect_backoff = reconnect_backoff
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._io_lock = asyncio.Lock()

        self.allowed_server_fingerprints = {
            normalize_cert_fingerprint(fingerprint)
            for fingerprint in (allowed_server_fingerprints or [])
        }

        self.setup_ssl(
            certfile,
            keyfile,
            certfile_server,
            check_hostname,
            minimum_tls_version,
            ciphers,
        )

    def setup_ssl(
        self,
        certfile: str,
        keyfile: str,
        certfile_server: str,
        check_hostname: bool,
        minimum_tls_version: ssl.TLSVersion,
        ciphers: Optional[str],
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
        self.ssl_ctx.minimum_version = minimum_tls_version
        if ciphers is not None:
            self.ssl_ctx.set_ciphers(ciphers)

    def _verify_server_fingerprint(self, writer: asyncio.StreamWriter) -> bool:
        """Verify the connected server certificate against the fingerprint allowlist.

        If no fingerprints were configured, the certificate trust decision is
        left to Python's TLS verification.
        """
        if not self.allowed_server_fingerprints:
            return True

        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return False

        cert = ssl_object.getpeercert(binary_form=True)
        if cert is None:
            return False

        return cert_fingerprint_matches(cert, self.allowed_server_fingerprints)

    @staticmethod
    def _writer_is_closing(writer: asyncio.StreamWriter | None) -> bool:
        """Return whether a stream writer is absent or already closing."""
        if writer is None:
            return True
        is_closing = getattr(writer, "is_closing", None)
        if is_closing is None:
            return False
        return is_closing()

    async def _close_writer(self, writer: asyncio.StreamWriter | None) -> None:
        """Close a stream writer and wait until the close completes."""
        if writer is None:
            return
        writer.close()
        await writer.wait_closed()

    async def close(self) -> None:
        """Close any reusable RadSec connection held by the client."""
        writer = self._writer
        self._reader = None
        self._writer = None
        await self._close_writer(writer)

    async def __aenter__(self) -> "RadSecClient":
        """Return this client for use as an async context manager."""
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """Close the reusable RadSec connection when leaving a context manager."""
        await self.close()

    async def _open_connection(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open and validate a TLS connection to the RadSec server."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.server, self.port, ssl=self.ssl_ctx),
            timeout=self.timeout,
        )

        logger.info(
            "Connected to RADSEC server on {}:{}",
            self.server,
            self.port,
        )

        if not self._verify_server_fingerprint(writer):
            await self._close_writer(writer)
            raise PacketError("Server certificate fingerprint is not allowed")

        return reader, writer

    async def _ensure_connection(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Return an existing reusable connection or open a new one."""
        if (
            self.reuse_connection
            and self._reader is not None
            and not self._writer_is_closing(self._writer)
        ):
            assert self._writer is not None
            return self._reader, self._writer

        await self.close()
        self._reader, self._writer = await self._open_connection()
        return self._reader, self._writer

    async def _write_packet(
        self, writer: asyncio.StreamWriter, packet: PacketImplementation
    ) -> None:
        """Write one RADIUS packet to the RadSec stream within the client timeout."""
        self._prepare_outgoing_packet(packet)
        writer.write(packet.request_packet())
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)

    def _prepare_outgoing_packet(self, packet: PacketImplementation) -> None:
        """Apply Message-Authenticator policy before a packet is sent."""
        prepare_request_message_authenticator(packet)

    async def _read_packet(self, reader: asyncio.StreamReader) -> bytes:
        """Read one RADIUS packet from the RadSec stream within the client timeout."""
        return await asyncio.wait_for(read_radius_packet(reader), timeout=self.timeout)

    async def _send_packet_once(self, packet: PacketImplementation) -> Optional[Packet]:
        """Send one RADIUS packet over the current connection strategy."""
        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter | None = None

        if self.reuse_connection:
            reader, writer = await self._ensure_connection()
        else:
            reader, writer = await self._open_connection()

        try:
            await self._write_packet(writer, packet)
            response = await self._read_packet(reader)

            logger.info("Received {} bytes from server", len(response))
            logger.debug("Response: {}", response.hex())

            reply = packet.create_reply(packet=response)
            if packet.verify_reply(reply, response):
                return reply

            raise PacketError("Received invalid RADSEC reply")
        finally:
            if not self.reuse_connection:
                await self._close_writer(writer)

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
        """Create a generic RADIUS packet with this client's dictionary and secret."""
        return Packet(id=id, dict=self.dict, secret=self.secret, **kwargs)

    async def _send_packet(self, packet: PacketImplementation) -> Optional[Packet]:
        """Send a packet to a RadSec server with timeout and reconnect handling.

        Args:
            packet (Packet): The packet to send
        """
        attempts = max(1, self.retries)
        retryable_errors = (
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
            ConnectionError,
            EOFError,
            OSError,
        )

        async with self._io_lock:
            for attempt in range(attempts):
                try:
                    return await self._send_packet_once(packet)
                except PacketError as exc:
                    logger.error("RADSEC packet error: {}", exc)
                    await self.close()
                    return None
                except retryable_errors as exc:
                    logger.warning(
                        "RADSEC request attempt {}/{} failed: {}",
                        attempt + 1,
                        attempts,
                        exc,
                    )
                    await self.close()

                if attempt + 1 < attempts and self.reconnect_backoff > 0:
                    await asyncio.sleep(self.reconnect_backoff)

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
                        CURRENT_ID,
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
