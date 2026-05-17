#!/usr/bin/env python
"""End-to-end Access-Request demo.

Spins up an async RADIUS server, sends one Access-Request from an async
client, prints both sides of the exchange, and exits. Run::

    python scenarios/auth.py

Set ``PYRAD2_TRACE=1`` to also dump every packet's wire bytes and
decoded AVPs as it crosses the loopback::

    PYRAD2_TRACE=1 python scenarios/auth.py
"""

import asyncio

from loguru import logger

from _shared import (
    AUTH_PORT,
    DEMO_HOST,
    DEMO_SECRET,
    banner,
    make_dictionary,
    make_remote_host,
    trace_hint,
)
from pyrad2.client_async import ClientAsync
from pyrad2.constants import PacketType
from pyrad2.server_async import ServerAsync


class DemoAuthServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):
        logger.info(
            "[server] Access-Request id={} from {} user-name={}",
            pkt.id,
            addr,
            pkt["User-Name"],
        )
        reply = self.create_reply_packet(
            pkt,
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "10.0.0.42",
            },
        )
        reply.code = PacketType.AccessAccept
        logger.info("[server] → Access-Accept id={}", pkt.id)
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        # Required abstract method on ServerAsync — unused here because
        # this scenario only enables the auth transport.
        pass


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoAuthServer(
        auth_port=AUTH_PORT,
        hosts={DEMO_HOST: make_remote_host()},
        dictionary=dictionary,
    )
    await server.initialize_transports(enable_auth=True)

    banner("Connecting client")
    client = ClientAsync(
        server=DEMO_HOST,
        auth_port=AUTH_PORT,
        secret=DEMO_SECRET,
        dict=dictionary,
        timeout=2,
    )
    await client.initialize_transports(enable_auth=True)

    try:
        banner("Sending Access-Request")
        req = client.create_auth_packet(User_Name="alice")
        req["NAS-IP-Address"] = "192.168.1.10"
        req["Service-Type"] = "Login-User"
        logger.info("[client] → Access-Request id={} user-name=alice", req.id)

        reply = await asyncio.wait_for(client.send_packet(req), timeout=2)

        banner("Reply received")
        verdict = (
            "Access-Accept"
            if reply.code == PacketType.AccessAccept
            else "Access-Reject"
        )
        logger.info("[client] ← {} id={}", verdict, reply.id)
        for key in reply.keys():
            logger.info("[client]   {}: {}", key, reply[key])
    finally:
        await client.deinitialize_transports()
        await server.deinitialize_transports()


if __name__ == "__main__":
    asyncio.run(main())
