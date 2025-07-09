import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, Optional

from loguru import logger

from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    Packet,
    PacketError,
)
from pyrad2.server import RemoteHost, ServerPacketError


class ServerType(Enum):
    Auth = "Authentication"
    Acct = "Accounting"
    Coa = "Coa"


class DatagramProtocolServer(asyncio.DatagramProtocol):
    def __init__(
        self,
        ip: str,
        port: int,
        server: "ServerAsync",
        server_type: ServerType,
        hosts: dict[str, RemoteHost],
        request_callback: Callable,
    ):
        self.ip = ip
        self.port = port
        self.server = server
        self.hosts = hosts
        self.server_type = server_type
        self.request_callback = request_callback
        self.transport: asyncio.DatagramTransport

    def connection_made(self, transport: asyncio.BaseTransport):
        self.transport = transport  # type: ignore
        logger.info("[{}:{}] Transport created", self.ip, self.port)

    def connection_lost(self, exc):
        if exc:
            logger.warning("[{}:{}] Connection lost: {}", self.ip, self.port, exc)
        else:
            logger.info("[{}:{}] Transport closed", self.ip, self.port)

    def send_response(self, reply: Packet, addr: str):
        self.transport.sendto(reply.ReplyPacket(), addr)

    def datagram_received(self, data, addr: tuple[str | Any, int]):
        logger.debug(
            "[{}:{}] Received {} bytes from {}", self.ip, self.port, len(data), addr
        )
        receive_date = datetime.utcnow()

        remote_host = self.hosts.get(addr[0], self.hosts.get("0.0.0.0"))
        if not remote_host:
            logger.warning(
                "[{}:{}] Drop packet from unknown source {}", self.ip, self.port, addr
            )
            return

        try:
            logger.debug(
                "[{}:{}] Received from {} packet: {}",
                self.ip,
                self.port,
                addr,
                data.hex(),
            )
            req = Packet(packet=data, dict=self.server.dict)

            if req.code in (
                PacketType.AccountingResponse,
                PacketType.AccessAccept,
                PacketType.AccessReject,
                PacketType.CoANAK,
                PacketType.CoAACK,
                PacketType.DisconnectNAK,
                PacketType.DisconnectACK,
            ):
                raise ServerPacketError(f"Invalid response packet {req.code}")

            if self.server_type == ServerType.Auth:
                if req.code != PacketType.AccessRequest:
                    raise ServerPacketError("Received non-auth packet on auth port")
                req = AuthPacket(
                    secret=remote_host.secret, dict=self.server.dict, packet=data
                )
                if self.server.enable_pkt_verify and not req.VerifyAuthRequest():
                    raise PacketError("Packet verification failed")

            elif self.server_type == ServerType.Coa:
                if req.code not in (
                    PacketType.DisconnectRequest,
                    PacketType.CoARequest,
                ):
                    raise ServerPacketError("Received non-coa packet on coa port")
                req = CoAPacket(
                    secret=remote_host.secret, dict=self.server.dict, packet=data
                )
                if self.server.enable_pkt_verify and not req.VerifyPacket():
                    raise PacketError("Packet verification failed")

            elif self.server_type == ServerType.Acct:
                if req.code != PacketType.AccountingRequest:
                    raise ServerPacketError("Received non-acct packet on acct port")
                req = AcctPacket(
                    secret=remote_host.secret, dict=self.server.dict, packet=data
                )
                if self.server.enable_pkt_verify and not req.VerifyPacket():
                    raise PacketError("Packet verification failed")

            self.request_callback(self, req, addr)
        except Exception as exc:
            if self.server.debug:
                logger.exception(
                    "[{}:{}] Error for packet from {}", self.ip, self.port, addr
                )
            else:
                logger.error(
                    "[{}:{}] Error for packet from {}: {}",
                    self.ip,
                    self.port,
                    addr,
                    exc,
                )

        process_date = datetime.utcnow()
        elapsed = (process_date - receive_date).microseconds / 1000
        logger.debug(
            "[{}:{}] Request from {} processed in {} ms",
            self.ip,
            self.port,
            addr,
            elapsed,
        )

    def error_received(self, exc):
        logger.error("[{}:{}] Error received: {}", self.ip, self.port, exc)

    async def close_transport(self):
        if self.transport:
            logger.debug("[{}:{}] Close transport...", self.ip, self.port)
            self.transport.close()
            self.transport = None

    def __call__(self):
        return self


class ServerAsync(ABC):
    """Basic async RADIUS server.

    This class implements the basics of a RADIUS server. It takes care
    of the details of receiving and decoding requests; processing of
    the requests should be done by overloading the appropriate methods
    in derived classes.
    """

    def __init__(
        self,
        auth_port: int = 1812,
        acct_port: int = 1813,
        coa_port: int = 3799,
        hosts: Optional[Dict[str, RemoteHost]] = None,
        dictionary: Optional[Dictionary] = None,
        enable_pkt_verify: bool = False,
        debug: bool = False,
    ):
        """Initialize an async server.

        Args:
            auth_port (int): Port to listen on for authentication packets.
            acct_port (int): Port to listen on for accounting packets.
            coa_port (int): Port to listen on for CoA packets.
            hosts (dict[str, RemoteHost]): Hosts who we can talk to. A dictionary mapping IP to RemoteHost class instances.
            dictionary (Dictionary): RADIUS dictionary to use.
            enable_pkt_verify (bool): If true, the packet will be verified against its secret
        """
        self.hosts = hosts or {}
        self.dict = dictionary
        self.enable_pkt_verify = enable_pkt_verify
        self.debug = debug

        self.auth_port = auth_port
        self.acct_port = acct_port
        self.coa_port = coa_port

        self.auth_protocols: list[asyncio.Protocol] = []
        self.acct_protocols: list[asyncio.Protocol] = []
        self.coa_protocols: list[asyncio.Protocol] = []

    def _request_handler(
        self, protocol: DatagramProtocolServer, req: Packet, addr: str
    ):
        try:
            if protocol.server_type == ServerType.Acct:
                self.handle_acct_packet(protocol, req, addr)
            elif protocol.server_type == ServerType.Auth:
                self.handle_auth_packet(protocol, req, addr)
            elif protocol.server_type == ServerType.Coa:
                if req.code == PacketType.CoARequest:
                    self.handle_coa_packet(protocol, req, addr)
                elif req.code == PacketType.DisconnectRequest:
                    self.handle_disconnect_packet(protocol, req, addr)
                else:
                    raise ServerPacketError("Unexpected CoA request type")
        except Exception as exc:
            msg = "[{}:{}] Unexpected error: {}".format(protocol.ip, protocol.port, exc)
            if self.debug:
                logger.exception(msg, protocol.ip, protocol.port, exc)
            else:
                logger.error(msg, protocol.ip, protocol.port, exc)

    async def initialize_transports(
        self,
        *,
        enable_acct: bool = False,
        enable_auth: bool = False,
        enable_coa: bool = False,
        addresses: Optional[list[str]] = None,
    ):
        if not any([enable_acct, enable_auth, enable_coa]):
            raise ValueError("No transports enabled")

        addresses = addresses or ["127.0.0.1"]
        tasks = []

        for addr in addresses:
            if enable_auth:
                tasks.append(
                    self._start_transport(
                        addr, self.auth_port, ServerType.Auth, self.auth_protocols
                    )
                )
            if enable_acct:
                tasks.append(
                    self._start_transport(
                        addr, self.acct_port, ServerType.Acct, self.acct_protocols
                    )
                )
            if enable_coa:
                tasks.append(
                    self._start_transport(
                        addr, self.coa_port, ServerType.Coa, self.coa_protocols
                    )
                )

        await asyncio.gather(*tasks)

    async def _start_transport(
        self, ip: str, port: int, server_type: ServerType, proto_list: list
    ):
        if any(proto.ip == ip for proto in proto_list):
            return
        protocol = DatagramProtocolServer(
            ip, port, self, server_type, self.hosts, self._request_handler
        )
        await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: protocol, local_addr=(ip, port), reuse_port=True
        )
        proto_list.append(protocol)

    async def deinitialize_transports(self):
        for proto_list in (
            self.auth_protocols,
            self.acct_protocols,
            self.coa_protocols,
        ):
            for proto in proto_list:
                await proto.close_transport()
            proto_list.clear()

    @staticmethod
    def create_reply_packet(pkt: Packet, **attributes) -> Packet:
        """Create a reply packet.
        Create a new packet which can be returned as a reply to a received
        packet.

        Args:
            pkt (packet.Packet): Packet to process
            attributes (dict): Custom attributes to be added to the reply
        """
        return pkt.CreateReply(**attributes)

    @abstractmethod
    def handle_auth_packet(
        self, protocol: DatagramProtocolServer, pkt: Packet, addr: str
    ):
        """Authentication packet handler.
        This is an empty function that is called when a valid
        authentication packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            protocol (DatagramProtocolServer): The protocol to use when sending responses
            pkt (packet.Packet): Packet to process
            addr (str): IP from the client
        """
        pass

    @abstractmethod
    def handle_acct_packet(
        self, protocol: DatagramProtocolServer, pkt: Packet, addr: str
    ):
        """Accounting packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            protocol (DatagramProtocolServer): The protocol to use when sending responses
            pkt (packet.Packet): Packet to process
            addr (str): IP from the client
        """
        pass

    @abstractmethod
    def handle_coa_packet(
        self, protocol: DatagramProtocolServer, pkt: Packet, addr: str
    ):
        """CoA packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            protocol (DatagramProtocolServer): The protocol to use when sending responses
            pkt (packet.Packet): Packet to process
            addr (str): IP from the client
        """
        pass

    @abstractmethod
    def handle_disconnect_packet(
        self, protocol: DatagramProtocolServer, pkt: Packet, addr: str
    ):
        """CoA packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            protocol (DatagramProtocolServer): The protocol to use when sending responses
            pkt (packet.Packet): Packet to process
            addr (str): IP from the client
        """
        pass
