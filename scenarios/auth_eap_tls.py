#!/usr/bin/env python
"""End-to-end EAP-TLS (RFC 5216) demo.

EAP-TLS authenticates both ends with X.509 certificates: the server
presents its cert during the TLS handshake, the supplicant presents
its own, and the EAP session reduces to running that handshake to
completion over EAP-Message AVPs. No password, no inner method —
when the handshake closes the server returns Access-Accept.

Run::

    python scenarios/auth_eap_tls.py

The demo uses the certs under ``examples/certs/`` (test-only;
locally-issued from the same CA). On a real deployment ``ca_cert``
points at the trust anchor for the AAA server's chain and
``client_cert`` / ``client_key`` are the supplicant's identity cert
issued under a CA the server trusts.

Wire-level walk-through of the exchange is logged at INFO. Set
``PYRAD2_TRACE=1`` to also dump the raw packet bytes.
"""

import asyncio

from loguru import logger

from _shared import (
    AUTH_PORT,
    DEMO_HOST,
    DEMO_SECRET,
    RADSEC_CA_CERT,
    RADSEC_CLIENT_CERT,
    RADSEC_CLIENT_KEY,
    RADSEC_SERVER_CERT,
    RADSEC_SERVER_KEY,
    attribute_bytes,
    banner,
    make_dictionary,
    make_remote_host,
    trace_hint,
)
from _tls_eap_demo_server import (
    TlsEapServerSession,
    fresh_state_cookie,
    joined_eap_message,
    split_eap_message_for_reply,
)
from pyrad2.client_async import ClientAsync
from pyrad2.constants import PacketType
from pyrad2.eap import register_method
from pyrad2.eap.tls import EAP_TYPE_TLS, TlsMethod
from pyrad2.server_async import ServerAsync


class DemoEapTlsServer(ServerAsync):
    """In-process EAP-TLS authenticator for the demo.

    Keeps one :class:`TlsEapServerSession` per outstanding ``State``
    cookie, drives the TLS handshake across however many
    Access-Challenge rounds the cert flight needs, and emits
    Access-Accept when the handshake completes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sessions: dict[bytes, TlsEapServerSession] = {}

    def handle_auth_packet(self, protocol, pkt, addr):
        # Inbound packet either starts a new conversation (no State,
        # carries EAP-Response/Identity) or continues one (State
        # cookie keys the per-session TLS engine).
        if "State" in pkt:
            self._continue_conversation(protocol, pkt, addr)
        else:
            self._begin_conversation(protocol, pkt, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        pass

    def _begin_conversation(self, protocol, pkt, addr):
        logger.info(
            "[server] new EAP-TLS conversation from {} (User-Name={})",
            addr,
            pkt.get("User-Name", ["?"])[0] if "User-Name" in pkt else "?",
        )
        session = TlsEapServerSession(
            server_cert=RADSEC_SERVER_CERT,
            server_key=RADSEC_SERVER_KEY,
            ca_cert=RADSEC_CA_CERT,
            eap_type=EAP_TYPE_TLS,
            require_client_cert=True,
        )
        state = fresh_state_cookie()
        self._sessions[state] = session
        self._send_challenge(protocol, pkt, addr, session.start_request_bytes(), state)

    def _continue_conversation(self, protocol, pkt, addr):
        old_state = attribute_bytes(pkt["State"][0])
        session = self._sessions.pop(old_state, None)
        if session is None:
            return self._reject(protocol, pkt, addr, "unknown State cookie")

        eap_payload = joined_eap_message(pkt)
        try:
            next_request = session.handle_eap_response(eap_payload)
        except Exception as exc:  # noqa: BLE001 — demo-grade error surfacing
            logger.warning("[server] EAP-TLS session failed: {}", exc)
            return self._reject(protocol, pkt, addr, str(exc))

        if session.complete:
            return self._send_accept(protocol, pkt, addr)

        new_state = fresh_state_cookie()
        self._sessions[new_state] = session
        self._send_challenge(protocol, pkt, addr, next_request or b"", new_state)

    def _send_challenge(self, protocol, pkt, addr, eap_request: bytes, state: bytes):
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.AccessChallenge
        reply["EAP-Message"] = split_eap_message_for_reply(eap_request)
        reply["State"] = state
        protocol.send_response(reply, addr)

    def _send_accept(self, protocol, pkt, addr):
        logger.info("[server] TLS handshake complete → Access-Accept")
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.AccessAccept
        protocol.send_response(reply, addr)

    def _reject(self, protocol, pkt, addr, reason: str):
        logger.warning("[server] rejecting: {}", reason)
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.AccessReject
        protocol.send_response(reply, addr)


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    # Register the EAP-TLS supplicant pointed at the same test certs
    # the server uses. The lambda is a factory — the registry calls it
    # once per conversation so each client gets a fresh TLS engine.
    register_method(
        "eap-tls",
        lambda: TlsMethod(
            ca_cert=RADSEC_CA_CERT,
            client_cert=RADSEC_CLIENT_CERT,
            client_key=RADSEC_CLIENT_KEY,
            identity=b"alice@example.com",
        ),
    )

    banner(f"Starting demo EAP-TLS server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoEapTlsServer(
        auth_port=AUTH_PORT,
        hosts={DEMO_HOST: make_remote_host()},
        dictionary=dictionary,
        # EAP-TLS conversations span many EAP-Message AVPs; the demo
        # server doesn't need the Message-Authenticator gate for this
        # scripted exchange.
        require_message_authenticator=False,
        enable_pkt_verify=False,
    )
    await server.initialize_transports(enable_auth=True)

    client = ClientAsync(
        server=DEMO_HOST,
        auth_port=AUTH_PORT,
        secret=DEMO_SECRET,
        dict=dictionary,
        timeout=2,
        enforce_ma=False,
    )
    await client.initialize_transports(enable_auth=True)

    try:
        banner("Sending EAP-TLS Access-Request")
        req = client.create_auth_packet(User_Name="alice@example.com")
        req["NAS-IP-Address"] = "192.168.1.10"
        # The whole opt-in. The client loop drives ``TlsMethod.start``
        # before the first send and ``TlsMethod.respond`` after every
        # Access-Challenge until the handshake closes and the server
        # responds Access-Accept.
        req.auth_type = "eap-tls"
        logger.info("[client] → Access-Request id={} (EAP-TLS)", req.id)

        reply = await asyncio.wait_for(client.send_packet(req), timeout=8)

        banner("Reply received")
        verdict = (
            "Access-Accept"
            if reply.code == PacketType.AccessAccept
            else "Access-Reject"
        )
        logger.info("[client] ← {} id={}", verdict, reply.id)
    finally:
        await client.deinitialize_transports()
        await server.deinitialize_transports()


if __name__ == "__main__":
    asyncio.run(main())
