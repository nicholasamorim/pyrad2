"""In-process EAP-TLS server harness for unit tests.

The harness wraps an ``ssl.MemoryBIO`` + ``SSLObject`` server-side so
the EAP-TLS, PEAP, and EAP-TTLS tests can drive a real TLS handshake
against pyrad2's supplicant methods without standing up FreeRADIUS.
It speaks the same EAP-TLS framing as the production wire, but bare-
bones — no RADIUS, no UDP, no router — so the assertions stay focused
on the EAP / TLS state machine.

Usage shape::

    server = TlsEapServer(
        server_cert="tests/certs/server/server.cert.pem",
        server_key="tests/certs/server/server.key.pem",
        ca_cert="tests/certs/ca/ca.cert.pem",   # for mTLS, EAP-TLS
        eap_type=EAP_TYPE_TLS,
    )
    request = server.start_request()             # EAP-Request/EAP-TLS, S=1
    method = TlsMethod(ssl_context=client_ctx)
    pkt = FakeAuthPacket()
    method.start(pkt)                            # EAP-Response/Identity
    # ... loop: server.advance(client_response) → next server request
    # ... method.respond(pkt, server_request)    → next client response
    assert server.handshake_done

The harness is intentionally a synchronous co-routine driven by the
test's outer for-loop, not a thread. That keeps the failure mode
``AssertionError on line N`` rather than ``test hung`` when something
goes wrong with the state machine.
"""

from __future__ import annotations

import ssl
from typing import Any

from pyrad2.eap._tls_eap import (
    EAP_MESSAGE_ATTR,
    STATE_ATTR,
    FLAG_START,
    build_eap_tls_response,
    fragment_outbound,
    join_eap_message_avps,
    parse_eap_tls_request,
    split_into_eap_message_avps,
)


class FakePacket:
    """Minimal dict-shaped stand-in for ``pyrad2.packet.Packet``.

    Real ``Packet`` requires a ``Dictionary`` and a code; the EAP
    methods only ever index by the attribute integer codes 79 and 24,
    so a bare dict subclass is enough. The harness emits these to the
    ``TlsMethod`` under test, and the method writes its responses
    back into the same shape.
    """

    def __init__(self) -> None:
        self._store: dict[int | str, Any] = {}

    def __contains__(self, key: int | str) -> bool:
        return key in self._store

    def __getitem__(self, key: int | str) -> Any:
        return self._store[key]

    def __setitem__(self, key: int | str, value: Any) -> None:
        self._store[key] = value


class FakeAuthPacket(FakePacket):
    """Same shape but also remembers an ``auth_type`` like ``AuthPacket``.

    EAP-TLS doesn't need ``auth_type`` itself — the dispatcher does —
    but having the attribute on the fake makes tests that exercise the
    full client loop drop in without modification.
    """

    def __init__(self) -> None:
        super().__init__()
        self.auth_type: str | None = None
        self.authenticator: bytes | None = None


class TlsEapServer:
    """EAP-TLS / PEAP / EAP-TTLS responder for use in tests.

    Drives a stdlib MemoryBIO TLS server through the EAP framing.
    Exposes two driving methods:

    * :meth:`start_request` — produces the initial server
      EAP-Request/EAP-TLS with the S bit set (RFC 5216 §2.1.3). The
      test pretends this came in as an Access-Challenge and hands it
      to the client method's ``respond``.
    * :meth:`handle_response` — accepts the client's reply, drives
      one step of the handshake, and returns the next server packet
      (or ``None`` when the handshake completed and the server would
      now emit Access-Accept).

    Fragmentation is supported on the outbound side — a Certificate
    flight that exceeds the 240-byte payload budget is split into
    multiple EAP-Request rounds with the L / M flags set correctly.
    Inbound fragments are reassembled before each handshake step.
    """

    def __init__(
        self,
        server_cert: str,
        server_key: str,
        ca_cert: str | None = None,
        eap_type: int = 13,
        require_client_cert: bool = True,
        inner_script: list[bytes] | None = None,
        inner_capture: list[bytes] | None = None,
        expected_inner_captures: int | None = None,
    ) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
        if require_client_cert:
            if ca_cert is None:
                raise ValueError(
                    "require_client_cert=True needs a CA bundle to verify against"
                )
            self._ctx.verify_mode = ssl.CERT_REQUIRED
            self._ctx.load_verify_locations(cafile=ca_cert)
        else:
            self._ctx.verify_mode = ssl.CERT_NONE

        self._inbound = ssl.MemoryBIO()
        self._outbound = ssl.MemoryBIO()
        self._sslobj: ssl.SSLObject = self._ctx.wrap_bio(
            self._inbound, self._outbound, server_side=True
        )

        self._eap_type = eap_type
        self._eap_id = 0
        self._state_token = b"\x00\x01\x02\x03"  # arbitrary, just round-trips
        self._inbound_fragments: list[tuple[int, bytes]] = []
        self._outbound_queue: list[tuple[int, bytes, int | None]] = []
        self.handshake_done = False
        # Post-handshake inner-EAP script (PEAP / EAP-TTLS). Each entry
        # is a payload the server sends through the TLS tunnel after
        # the handshake completes; client responses are captured into
        # ``inner_capture`` (when provided) so tests can assert on
        # exactly what the supplicant returned.
        self._inner_script: list[bytes] = list(inner_script or [])
        self._inner_capture = inner_capture if inner_capture is not None else []
        self._inner_first_sent = False
        # PEAP's inner exchange is a request/response ping-pong, so by
        # default we expect one capture per scripted request. EAP-TTLS
        # has the supplicant push AVPs unprompted (no inbound request
        # to answer), so callers pass ``expected_inner_captures=1``
        # with an empty script to wait for that single push.
        if expected_inner_captures is None:
            expected_inner_captures = len(self._inner_script)
        self._expected_inner_captures = expected_inner_captures
        self._inner_done = False

    def _next_eap_id(self) -> int:
        # EAP id rolls one-up per Request the server emits. The
        # supplicant echoes it back, the server bumps for the next.
        self._eap_id = (self._eap_id + 1) % 256
        return self._eap_id

    def start_request(self) -> FakePacket:
        """Produce the opening EAP-Request/EAP-TLS, S=1, body empty."""
        body = build_eap_tls_response(
            eap_id=self._next_eap_id(),
            eap_type=self._eap_type,
            flags=FLAG_START,
            tls_bytes=b"",
        )
        # Server-emitted EAP packets use code=1 (Request), not 2; flip
        # the first byte after the helper packed code=2.
        body = bytes([1]) + body[1:]
        pkt = FakePacket()
        pkt[EAP_MESSAGE_ATTR] = split_into_eap_message_avps(body)
        pkt[STATE_ATTR] = [self._state_token]
        return pkt

    def handle_response(self, client_pkt: FakeAuthPacket) -> FakePacket | None:
        """Process one client EAP-Response and emit the next Request.

        Returns ``None`` when the TLS handshake just completed on this
        round — the test treats that as the moment the production
        server would send Access-Accept.
        """
        eap_payload = join_eap_message_avps(client_pkt[EAP_MESSAGE_ATTR])
        # Strip the code byte (which is RESPONSE=2 from the client)
        # and rebuild as if we were reading an inbound TLS-EAP packet.
        # parse_eap_tls_request doesn't care about the code field; it
        # reads from byte 1 onwards.
        _eap_id, eap_type, flags, body = parse_eap_tls_request(eap_payload)
        if eap_type != self._eap_type:
            raise ValueError(
                f"Server harness got EAP-Type {eap_type}, expected {self._eap_type}"
            )

        self._inbound_fragments.append((flags, body))
        if flags & 0x40:  # M (More) — wait for the rest before driving TLS
            return self._build_ack_request()

        # Final fragment arrived: reassemble, feed the TLS stack, step.
        joined = b"".join(b for _, b in self._inbound_fragments)
        self._inbound_fragments.clear()
        if joined:
            self._inbound.write(joined)
        try:
            self._sslobj.do_handshake()
            self.handshake_done = True
        except ssl.SSLWantReadError:
            pass

        # Post-handshake inner-EAP exchange (PEAP / EAP-TTLS). Drains
        # any plaintext the client just sent, captures it for the
        # test, then writes the next scripted inner request. The
        # ``expected_inner_captures`` arm catches the EAP-TTLS shape
        # where the client pushes inner AVPs unprompted (no script
        # item to mark the conversation in flight).
        if self.handshake_done and (
            self._inner_script
            or self._inner_first_sent
            or self._expected_inner_captures > 0
        ):
            self._pump_inner_exchange()

        # If we still have outbound TLS bytes queued from a previous
        # round (multi-fragment flight), serve the next one.
        if not self._outbound_queue:
            pending = self._outbound.read()
            if pending:
                self._outbound_queue = fragment_outbound(pending)

        if self._outbound_queue:
            flags_out, chunk, total_length = self._outbound_queue.pop(0)
            return self._build_request(flags_out, chunk, total_length)

        # Nothing more to send. If the inner exchange is done (or
        # there never was one and the handshake completed with no
        # captures expected), the production server would now emit
        # Access-Accept — represent that as None.
        if self._inner_done or (
            self.handshake_done
            and not self._inner_script
            and self._expected_inner_captures == 0
        ):
            return None
        # Otherwise emit a zero-payload Request to ACK and let the
        # client send more (e.g. its Finished after our ChangeCipherSpec,
        # or TTLS-style inner AVPs unprompted).
        return self._build_ack_request()

    def _pump_inner_exchange(self) -> None:
        """Run one step of the post-handshake inner-EAP exchange.

        The TLS engine has already absorbed the client's encrypted
        payload via the inbound BIO. We pull whatever plaintext it
        decoded, capture it for the test to assert on, then — only if
        the client actually sent us something — write the next
        scripted inner-EAP request out of the TLS layer for the next
        round.

        The "only if we got plaintext back" gate matters: an EAP-TLS
        fragmented flight produces several intermediate round-trips
        where the client just ACKs without any TLS application data,
        and the server must not blindly drain the inner script across
        those empty ACKs.
        """
        # Drain any decrypted application data the client wrote.
        try:
            decrypted = self._sslobj.read(16384)
        except ssl.SSLWantReadError:
            decrypted = b""
        if decrypted:
            self._inner_capture.append(decrypted)

        if self._inner_done:
            return

        # Termination: enough captures collected AND nothing more to
        # send. Works for both PEAP (N captures = N script items) and
        # EAP-TTLS (1 capture, 0 script items).
        if (
            not self._inner_script
            and len(self._inner_capture) >= self._expected_inner_captures
        ):
            self._inner_done = True
            return

        # First inner round: emit the opening server request (typically
        # an EAP-Request/Identity) the moment the handshake completes.
        if not self._inner_first_sent:
            self._inner_first_sent = True
            if self._inner_script:
                self._sslobj.write(self._inner_script.pop(0))
            return

        # Subsequent rounds: only advance the script when we actually
        # received the client's response to the prior request.
        if not decrypted:
            return

        if self._inner_script:
            self._sslobj.write(self._inner_script.pop(0))

    def _build_request(
        self,
        flags: int,
        body: bytes,
        total_length: int | None,
    ) -> FakePacket:
        eap = build_eap_tls_response(
            eap_id=self._next_eap_id(),
            eap_type=self._eap_type,
            flags=flags,
            tls_bytes=body,
            total_length=total_length,
        )
        # Flip code byte from Response(2) to Request(1).
        eap = bytes([1]) + eap[1:]
        pkt = FakePacket()
        pkt[EAP_MESSAGE_ATTR] = split_into_eap_message_avps(eap)
        pkt[STATE_ATTR] = [self._state_token]
        return pkt

    def _build_ack_request(self) -> FakePacket:
        """Server-side ACK: empty-body EAP-Request with no flags set."""
        return self._build_request(flags=0, body=b"", total_length=None)
