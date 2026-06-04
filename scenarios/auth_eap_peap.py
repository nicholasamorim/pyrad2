#!/usr/bin/env python
"""End-to-end PEAPv0 (draft-josefsson) demo with EAP-MD5 inner method.

PEAP wraps a second EAP exchange inside the TLS tunnel. The outer
handshake authenticates the server only (no client cert), then the
server tunnels an inner EAP-Request/Identity, an inner EAP-Request
for the configured method, and finally a Result-TLV success
indication. The supplicant decrypts each inner Request, drives the
inner ``EapMethod`` via the registry, and encrypts the reply back
through the same tunnel.

This demo uses **EAP-MD5** as the inner method to keep the scenario
dependency-free — ``cryptography`` isn't required. Production
deployments typically use EAP-MSCHAPv2 (``pip install pyrad2[mschap]``
and switch the ``inner_method`` argument).

Run::

    python scenarios/auth_eap_peap.py
"""

import asyncio
import hashlib
import secrets
import struct

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
from pyrad2.constants import EAPPacketType, EAPType, PacketType
from pyrad2.eap import register_method
from pyrad2.eap.peap import (
    EAP_TYPE_PEAP,
    PEAP_TLV_RESULT,
    PEAP_TLV_STATUS_SUCCESS,
    PEAP_TLV_TYPE,
    PeapMethod,
)
from pyrad2.server_async import ServerAsync

DEMO_USER = b"alice"
DEMO_PASSWORD = b"clientPass"

EAP_TYPE_MD5 = 4


def _eap_request_identity(eap_id: int) -> bytes:
    return struct.pack("!BBHB", EAPPacketType.REQUEST, eap_id, 5, EAPType.IDENTITY)


def _eap_request_md5(eap_id: int, challenge: bytes) -> bytes:
    """RFC 3748 §5.4 — type(4) + size(1) + challenge(N)."""
    return (
        struct.pack(
            "!BBHBB",
            EAPPacketType.REQUEST,
            eap_id,
            5 + 1 + len(challenge),
            EAP_TYPE_MD5,
            len(challenge),
        )
        + challenge
    )


def _peap_tlv_success(eap_id: int) -> bytes:
    """Inner EAP-Request carrying a PEAPv0 Result-TLV (status=Success)."""
    return struct.pack(
        "!BBHB HH H",
        EAPPacketType.REQUEST,
        eap_id,
        11,
        PEAP_TLV_TYPE,
        PEAP_TLV_RESULT,
        2,
        PEAP_TLV_STATUS_SUCCESS,
    )


class _PeapInnerExchange:
    """Tiny state machine driving the server side of the inner exchange.

    Identity → MD5 challenge → MD5 verify → Result-TLV. Each step's
    result feeds the previous step's response into the verifier so
    the demo actually validates the password rather than always
    rubber-stamping.
    """

    def __init__(self, password: bytes) -> None:
        self._password = password
        self._md5_challenge = secrets.token_bytes(16)
        self._md5_eap_id = 0
        self._stage = "identity"

    def __call__(self, decrypted: bytes, write_response) -> bool:
        if self._stage == "identity":
            # Supplicant just returned EAP-Response/Identity carrying
            # the real User-Name. Bump to the MD5 challenge.
            logger.info(
                "[server] inner Identity received ({} bytes); → MD5-Challenge",
                len(decrypted),
            )
            self._md5_eap_id = (decrypted[1] + 1) % 256
            write_response(_eap_request_md5(self._md5_eap_id, self._md5_challenge))
            self._stage = "md5"
            return False

        if self._stage == "md5":
            # Supplicant returned EAP-Response/MD5-Challenge with the
            # digest. Verify it against DEMO_PASSWORD.
            if len(decrypted) < 22 or decrypted[4] != EAP_TYPE_MD5:
                logger.warning("[server] malformed inner EAP-MD5 response")
                return True
            received_eap_id = decrypted[1]
            received_digest = decrypted[6:22]
            expected = hashlib.md5(
                bytes([received_eap_id]) + self._password + self._md5_challenge
            ).digest()
            if received_digest != expected:
                logger.warning("[server] inner MD5 digest mismatch → Failure")
                # In a real server we'd send Result-TLV failure and
                # then outer EAP-Failure. The demo just closes out.
                return True
            logger.info("[server] inner MD5 digest matched → Result-TLV Success")
            write_response(_peap_tlv_success((received_eap_id + 1) % 256))
            self._stage = "tlv"
            return False

        if self._stage == "tlv":
            # Supplicant echoed the Result-TLV — server is now free
            # to emit outer Access-Accept.
            logger.info("[server] inner Result-TLV echoed → conversation done")
            return True

        return True


class DemoEapPeapServer(ServerAsync):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sessions: dict[bytes, TlsEapServerSession] = {}

    def handle_auth_packet(self, protocol, pkt, addr):
        if "State" in pkt:
            self._continue(protocol, pkt, addr)
        else:
            self._begin(protocol, pkt, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        pass

    def _begin(self, protocol, pkt, addr):
        logger.info("[server] new PEAP conversation from {}", addr)
        # Server-only TLS auth is canonical PEAP; no client cert
        # required, and the inner method takes care of user auth.
        session = TlsEapServerSession(
            server_cert=RADSEC_SERVER_CERT,
            server_key=RADSEC_SERVER_KEY,
            eap_type=EAP_TYPE_PEAP,
            require_client_cert=False,
            inner_handler=_PeapInnerExchange(password=DEMO_PASSWORD),
            first_inner_payload=_eap_request_identity(eap_id=10),
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
        logger.info("[server] PEAP exchange complete → Access-Accept")
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
        "eap-peap",
        lambda: PeapMethod(
            ca_cert=RADSEC_CA_CERT,
            outer_identity=b"anonymous",
            inner_method="eap-md5",
        ),
    )

    banner(f"Starting demo PEAP server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoEapPeapServer(
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
        banner("Sending PEAP Access-Request")
        # PEAP inner EAP-MD5 reuses ``User-Password`` from the outer
        # packet (the inner method reads it for the digest input).
        req = client.create_auth_packet(
            User_Name=DEMO_USER.decode(),
            User_Password=DEMO_PASSWORD.decode(),
        )
        req["NAS-IP-Address"] = "192.168.1.10"
        req.auth_type = "eap-peap"
        logger.info("[client] → Access-Request id={} (PEAPv0 / EAP-MD5)", req.id)

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
