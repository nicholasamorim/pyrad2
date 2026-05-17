#!/usr/bin/env python
"""End-to-end Accounting-Request demo.

Sends a single Accounting-Start packet from an async client to an async
server running in the same process, prints both sides, and exits.
"""

import asyncio

from loguru import logger

from _shared import (
    ACCT_PORT,
    DEMO_HOST,
    DEMO_SECRET,
    banner,
    make_dictionary,
    make_remote_host,
    trace_hint,
)
from pyrad2.client_async import ClientAsync
from pyrad2.server_async import ServerAsync


class DemoAcctServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):
        # Required abstract method on ServerAsync — unused here.
        pass

    def handle_acct_packet(self, protocol, pkt, addr):
        logger.info(
            "[server] Accounting-Request id={} from {} status-type={}",
            pkt.id,
            addr,
            pkt["Acct-Status-Type"],
        )
        reply = self.create_reply_packet(pkt)
        logger.info("[server] → Accounting-Response id={}", pkt.id)
        protocol.send_response(reply, addr)


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo accounting server on {DEMO_HOST}:{ACCT_PORT}")
    server = DemoAcctServer(
        acct_port=ACCT_PORT,
        hosts={DEMO_HOST: make_remote_host()},
        dictionary=dictionary,
    )
    await server.initialize_transports(enable_acct=True)

    banner("Connecting client")
    client = ClientAsync(
        server=DEMO_HOST,
        acct_port=ACCT_PORT,
        secret=DEMO_SECRET,
        dict=dictionary,
        timeout=2,
    )
    await client.initialize_transports(enable_acct=True)

    try:
        banner("Sending Accounting-Request (Start)")
        req = client.create_acct_packet(User_Name="alice")
        req["NAS-IP-Address"] = "192.168.1.10"
        req["Acct-Status-Type"] = "Start"
        req["Acct-Session-Id"] = "demo-session-001"
        logger.info("[client] → Accounting-Request id={} Start", req.id)

        reply = await asyncio.wait_for(client.send_packet(req), timeout=2)

        banner("Reply received")
        logger.info("[client] ← Accounting-Response id={}", reply.id)
    finally:
        await client.deinitialize_transports()
        await server.deinitialize_transports()


if __name__ == "__main__":
    asyncio.run(main())
