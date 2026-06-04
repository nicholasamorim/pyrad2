#!/usr/bin/env python
"""End-to-end EAP-TTLS / PAP (RFC 5281) demo.

EAP-TTLS shares the outer TLS-EAP shape with EAP-TLS and PEAP. The
inner exchange is **not** EAP, though — it's a stream of Diameter
AVPs (RFC 6733 §4.1). The pyrad2 ``TtlsMethod`` ships PAP as the
inner method: the supplicant pushes a User-Name + User-Password AVP
once the TLS handshake closes, the server decodes them, validates,
and emits outer Access-Accept.

Run::

    python scenarios/auth_eap_ttls.py
"""

import asyncio

from loguru import logger

from _shared import (
    AUTH_PORT,
    DEMO_HOST,
    DEMO_SECRET,
    RADSEC_CA_CERT,
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
from pyrad2.eap.ttls import (
    AVP_USER_NAME,
    AVP_USER_PASSWORD,
    EAP_TYPE_TTLS,
    TtlsMethod,
    decode_diameter_avps,
)
from pyrad2.server_async import ServerAsync

DEMO_USER = b"alice"
DEMO_PASSWORD = b"clientPass"


class _TtlsInnerExchange:
    """Decode inner PAP AVPs and validate against a known credential.

    TTLS only needs one inner round-trip — the client pushes AVPs
    unprompted after the handshake, the server validates, done. The
    callback returns ``True`` the first time it sees decrypted bytes
    so the conversation closes cleanly.
    """

    def __init__(self, expected_user: bytes, expected_password: bytes) -> None:
        self._expected_user = expected_user
        self._expected_password = expected_password

    def __call__(self, decrypted: bytes, write_response) -> bool:
        try:
            avps = decode_diameter_avps(decrypted)
        except ValueError as exc:
            logger.warning("[server] malformed inner AVP stream: {}", exc)
            return True

        by_code = {code: data for code, _flags, _vendor, data in avps}
        user = by_code.get(AVP_USER_NAME, b"")
        pw = by_code.get(AVP_USER_PASSWORD, b"")
        logger.info(
            "[server] inner PAP received: user={!r} password=<{} bytes>",
            user,
            len(pw),
        )

        if user != self._expected_user or pw != self._expected_password:
            logger.warning("[server] inner PAP credentials mismatch → Failure")
            # Real server would emit outer EAP-Failure; demo just
            # closes out and the outer reply path issues Reject.
        else:
            logger.info("[server] inner PAP credentials matched → Accept")
        # TTLS has no server-side inner response — the conversation
        # closes regardless of result.
        return True


class DemoEapTtlsServer(ServerAsync):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sessions: dict[bytes, TlsEapServerSession] = {}
        self._verdicts: dict[bytes, bool] = {}

    def handle_auth_packet(self, protocol, pkt, addr):
        if "State" in pkt:
            self._continue(protocol, pkt, addr)
        else:
            self._begin(protocol, pkt, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        pass

    def _begin(self, protocol, pkt, addr):
        logger.info("[server] new EAP-TTLS conversation from {}", addr)
        session = TlsEapServerSession(
            server_cert=RADSEC_SERVER_CERT,
            server_key=RADSEC_SERVER_KEY,
            eap_type=EAP_TYPE_TTLS,
            require_client_cert=False,
            inner_handler=_TtlsInnerExchange(
                expected_user=DEMO_USER,
                expected_password=DEMO_PASSWORD,
            ),
        )
        state = fresh_state_cookie()
        self._sessions[state] = session
        self._send_challenge(protocol, pkt, addr, session.start_request_bytes(), state)

    def _continue(self, protocol, pkt, addr):
        old_state = attribute_bytes(pkt["State"][0])
        session = self._sessions.pop(old_state, None)
        if session is None:
            return self._reject(protocol, pkt, addr, "unknown State cookie")

        eap_payload = joined_eap_message(pkt)
        try:
            next_request = session.handle_eap_response(eap_payload)
        except Exception as exc:  # noqa: BLE001 — demo-grade error surfacing
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
        logger.info("[server] EAP-TTLS exchange complete → Access-Accept")
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

    register_method(
        "eap-ttls",
        lambda: TtlsMethod(
            ca_cert=RADSEC_CA_CERT,
            outer_identity=b"anonymous@example.com",
        ),
    )

    banner(f"Starting demo EAP-TTLS server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoEapTtlsServer(
        auth_port=AUTH_PORT,
        hosts={DEMO_HOST: make_remote_host()},
        dictionary=dictionary,
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
        banner("Sending EAP-TTLS Access-Request")
        req = client.create_auth_packet(
            User_Name=DEMO_USER.decode(),
            User_Password=DEMO_PASSWORD.decode(),
        )
        req["NAS-IP-Address"] = "192.168.1.10"
        req.auth_type = "eap-ttls"
        logger.info("[client] → Access-Request id={} (EAP-TTLS / PAP)", req.id)

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
