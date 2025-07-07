__docformat__ = "epytext en"

import asyncio
import random
from datetime import datetime
from typing import Optional

from loguru import logger

from pyrad2.dictionary import Dictionary
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    Packet,
    PacketImplementation,
)


class DatagramProtocolClient(asyncio.Protocol):
    def __init__(
        self,
        server: str,
        port: int,
        client: "ClientAsync",
        retries: int = 3,
        timeout: int = 30,
    ):
        self.port = port
        self.server = server
        self.retries = retries
        self.timeout = timeout
        self.client = client

        # Map of pending requests
        self.pending_requests: dict[int, dict] = {}

        # Use cryptographic-safe random generator as provided by the OS.
        random_generator = random.SystemRandom()
        self.packet_id = random_generator.randrange(0, 256)

        self.timeout_future = None

    async def __timeout_handler__(self):
        try:
            while True:
                req2delete = []
                now = datetime.now()
                next_weak_up = self.timeout

                for id, req in self.pending_requests.items():
                    secs = (req["send_date"] - now).seconds
                    if secs > self.timeout:
                        if req["retries"] == self.retries:
                            logger.debug(
                                "[{}:{}] For request {} execute all retries",
                                self.server,
                                self.port,
                                id,
                            )
                            req["future"].set_exception(
                                TimeoutError("Timeout on Reply")
                            )
                            req2delete.append(id)
                        else:
                            # Send again packet
                            req["send_date"] = now
                            req["retries"] += 1
                            logger.debug(
                                "[{}:{}] For request {} execute retry {}",
                                self.server,
                                self.port,
                                id,
                                req["retries"],
                            )
                            self.transport.sendto(req["packet"].RequestPacket())
                    elif next_weak_up > secs:
                        next_weak_up = secs

                for id in req2delete:
                    # Remove request for map
                    del self.pending_requests[id]

                await asyncio.sleep(next_weak_up)

        except asyncio.CancelledError:
            pass

    def send_packet(self, packet: PacketImplementation, future: asyncio.Future):
        if packet.id in self.pending_requests:
            raise Exception("Packet with id %d already present" % packet.id)

        # Store packet on pending requests map
        self.pending_requests[packet.id] = {
            "packet": packet,
            "creation_date": datetime.now(),
            "retries": 0,
            "future": future,
            "send_date": datetime.now(),
        }

        # In queue packet raw on socket buffer
        self.transport.sendto(packet.RequestPacket())

    def connection_made(self, transport: asyncio.BaseTransport):
        assert isinstance(transport, asyncio.DatagramTransport), (
            "Expected DatagramTransport"
        )
        self.transport: asyncio.DatagramTransport = transport

        socket = transport.get_extra_info("socket")
        logger.info(
            "[{}:{}] Transport created with binding in {}:{}",
            self.server,
            self.port,
            socket.getsockname()[0],
            socket.getsockname()[1],
        )

        # loop = asyncio.get_event_loop()
        # asyncio.set_event_loop(loop=asyncio.get_event_loop())
        # Start asynchronous timer handler
        self.timeout_future = asyncio.ensure_future(self.__timeout_handler__())
        # asyncio.set_event_loop(loop=pre_loop)

    def error_received(self, exc: Exception) -> None:
        logger.error("[{}:{}] Error received: {}", self.server, self.port, exc)

    def connection_lost(self, exc) -> None:
        if exc:
            logger.warning(
                "[{}:{}] Connection lost: {}", self.server, self.port, str(exc)
            )
        else:
            logger.info("[{}:{}] Transport closed", self.server, self.port)

    def datagram_received(self, data: bytes, addr: str):
        try:
            reply = Packet(packet=data, dict=self.client.dict)

            if reply.code and reply.id in self.pending_requests:
                req = self.pending_requests[reply.id]
                packet = req["packet"]

                reply.dict = packet.dict
                reply.secret = packet.secret

                if packet.VerifyReply(reply, data):
                    req["future"].set_result(reply)
                    # Remove request for map
                    del self.pending_requests[reply.id]
                else:
                    logger.warning(
                        "[{}:{}] Ignore invalid reply for id {}: {}",
                        self.server,
                        self.port,
                        reply.id,
                        data,
                    )
            else:
                logger.warning(
                    "[{}:{}] Ignore invalid reply: {}", self.server, self.port, data
                )

        except Exception as exc:
            logger.error(
                "[{}:{}] Error on decode packet: {}", self.server, self.port, exc
            )

    async def close_transport(self) -> None:
        if self.transport:
            logger.debug("[{}:{}] Closing transport...", self.server, self.port)
            self.transport.close()
            self.transport = None  # type: ignore
        if self.timeout_future:
            self.timeout_future.cancel()
            await self.timeout_future
            self.timeout_future = None

    def create_id(self) -> int:
        self.packet_id = (self.packet_id + 1) % 256
        return self.packet_id

    def __str__(self) -> str:
        return "DatagramProtocolClient(server?=%s, port=%d)" % (self.server, self.port)

    # Used as protocol_factory
    def __call__(self):
        return self


class ClientAsync:
    """Basic RADIUS client.
    This class implements a basic RADIUS client. It can send requests
    to a RADIUS server, taking care of timeouts and retries, and
    validate its replies.
    """

    def __init__(
        self,
        server: str,
        auth_port: int = 1812,
        acct_port: int = 1813,
        coa_port: int = 3799,
        secret: bytes = b"",
        dict: Optional[Dictionary] = None,
        retries: int = 3,
        timeout: int = 30,
    ):
        """Initializes an async RADIUS client.

        Args:
            server (str): Hostname or IP address of the RADIUS server.
            auth_port (int): Port to use for authentication packets.
            acct_port (int): Port to use for accounting packets.
            coa_port (int): Port to use for CoA packets.
            secret (bytes): RADIUS secret.
            dict (pyrad.dictionary.Dictionary): RADIUS dictionary.
            retries (int): Number of times to retry sending a RADIUS request.
            timeout (int): Number of seconds to wait for an answer.
        """
        self.server = server
        self.secret = secret
        self.retries = retries
        self.timeout = timeout
        self.dict = dict

        self.auth_port = auth_port
        self.protocol_auth: Optional[DatagramProtocolClient] = None

        self.acct_port = acct_port
        self.protocol_acct: Optional[DatagramProtocolClient] = None

        self.protocol_coa: Optional[DatagramProtocolClient] = None
        self.coa_port = coa_port

    async def initialize_transports(
        self,
        enable_acct: bool = False,
        enable_auth: bool = False,
        enable_coa: bool = False,
        local_addr: Optional[str] = None,
        local_auth_port: Optional[int] = None,
        local_acct_port: Optional[int] = None,
        local_coa_port: Optional[int] = None,
    ):
        task_list = []

        if not enable_acct and not enable_auth and not enable_coa:
            raise Exception("No transports selected")

        loop = asyncio.get_event_loop()
        if enable_acct and not self.protocol_acct:
            self.protocol_acct = DatagramProtocolClient(
                self.server,
                self.acct_port,
                self,
                retries=self.retries,
                timeout=self.timeout,
            )
            bind_addr = None
            if local_addr and local_acct_port:
                bind_addr = (local_addr, local_acct_port)

            acct_connect = loop.create_datagram_endpoint(
                self.protocol_acct,
                reuse_port=True,
                remote_addr=(self.server, self.acct_port),
                local_addr=bind_addr,
            )
            task_list.append(acct_connect)

        if enable_auth and not self.protocol_auth:
            self.protocol_auth = DatagramProtocolClient(
                self.server,
                self.auth_port,
                self,
                retries=self.retries,
                timeout=self.timeout,
            )
            bind_addr = None
            if local_addr and local_auth_port:
                bind_addr = (local_addr, local_auth_port)

            auth_connect = loop.create_datagram_endpoint(
                self.protocol_auth,
                reuse_port=True,
                remote_addr=(self.server, self.auth_port),
                local_addr=bind_addr,
            )
            task_list.append(auth_connect)

        if enable_coa and not self.protocol_coa:
            self.protocol_coa = DatagramProtocolClient(
                self.server,
                self.coa_port,
                self,
                retries=self.retries,
                timeout=self.timeout,
            )
            bind_addr = None
            if local_addr and local_coa_port:
                bind_addr = (local_addr, local_coa_port)

            coa_connect = loop.create_datagram_endpoint(
                self.protocol_coa,
                reuse_port=True,
                remote_addr=(self.server, self.coa_port),
                local_addr=bind_addr,
            )
            task_list.append(coa_connect)

        await asyncio.ensure_future(
            asyncio.gather(
                *task_list,
                return_exceptions=False,
            ),
            loop=loop,
        )

    async def deinitialize_transports(
        self,
        deinit_coa: bool = True,
        deinit_auth: bool = True,
        deinit_acct: bool = True,
    ) -> None:
        if self.protocol_coa and deinit_coa:
            await self.protocol_coa.close_transport()
            del self.protocol_coa
            self.protocol_coa = None
        if self.protocol_auth and deinit_auth:
            await self.protocol_auth.close_transport()
            del self.protocol_auth
            self.protocol_auth = None
        if self.protocol_acct and deinit_acct:
            await self.protocol_acct.close_transport()
            del self.protocol_acct
            self.protocol_acct = None

    def CreateAuthPacket(self, **args) -> AuthPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """
        if not self.protocol_auth:
            raise Exception("Transport not initialized")

        return AuthPacket(
            dict=self.dict,
            id=self.protocol_auth.create_id(),
            secret=self.secret,
            **args,
        )

    def CreateAcctPacket(self, **args) -> AcctPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """
        if not self.protocol_acct:
            raise Exception("Transport not initialized")

        return AcctPacket(
            id=self.protocol_acct.create_id(),
            dict=self.dict,
            secret=self.secret,
            **args,
        )

    def CreateCoAPacket(self, **args) -> CoAPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """

        if not self.protocol_coa:
            raise Exception("Transport not initialized")

        return CoAPacket(
            id=self.protocol_coa.create_id(), dict=self.dict, secret=self.secret, **args
        )

    def CreatePacket(self, id: int, **args) -> Packet:
        if not id:
            raise Exception("Missing mandatory packet id")

        return Packet(id=id, dict=self.dict, secret=self.secret, **args)

    def SendPacket(self, pkt: Packet) -> asyncio.Future:
        """Send a packet to a RADIUS server.

        Args:
            pkt (Packet): The packet to send

        Returns:
            asyncio.Future: Future related with packet to send
        """

        ans: asyncio.Future = asyncio.Future(loop=asyncio.get_event_loop())

        if isinstance(pkt, AuthPacket):
            if not self.protocol_auth:
                raise Exception("Transport not initialized")

            self.protocol_auth.send_packet(pkt, ans)

        elif isinstance(pkt, AcctPacket):
            if not self.protocol_acct:
                raise Exception("Transport not initialized")

            self.protocol_acct.send_packet(pkt, ans)

        elif isinstance(pkt, CoAPacket):
            if not self.protocol_coa:
                raise Exception("Transport not initialized")

            self.protocol_coa.send_packet(pkt, ans)

        else:
            raise Exception("Unsupported packet")

        return ans
