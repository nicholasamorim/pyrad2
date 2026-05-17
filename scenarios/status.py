#!/usr/bin/env python
"""End-to-end Status-Server (RFC 5997) health-check demo.

Sends a Status-Server packet to the authentication port. The server
replies with Access-Accept *without* invoking handle_auth_packet — RFC
5997 says health checks must not exercise the normal request handlers.
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


class DemoStatusServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):
        # Status-Server probes never get here — the framework intercepts
        # them and replies in create_status_response. If you see this log
        # line during the demo, something is wrong.
        logger.error("[server] handle_auth_packet should not be reached for status")

    def handle_acct_packet(self, protocol, pkt, addr):
        # Required abstract method on ServerAsync — unused here.
        pass


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoStatusServer(
        auth_port=AUTH_PORT,
        hosts={DEMO_HOST: make_remote_host()},
        dictionary=dictionary,
        require_message_authenticator=True,
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
        banner("Sending Status-Server probe")
        probe = client.create_status_packet()
        logger.info("[client] → Status-Server id={}", probe.id)

        reply = await asyncio.wait_for(client.send_packet(probe), timeout=2)

        banner("Reply received")
        verdict = (
            "Access-Accept (server is up)"
            if reply.code == PacketType.AccessAccept
            else f"code={reply.code}"
        )
        logger.info("[client] ← {} id={}", verdict, reply.id)
    finally:
        await client.deinitialize_transports()
        await server.deinitialize_transports()


if __name__ == "__main__":
    asyncio.run(main())
