"""Shared in-process TLS-EAP server session for the demo scenarios.

The three TLS-EAP scenarios (``auth_eap_tls.py``,
``auth_eap_peap.py``, ``auth_eap_ttls.py``) each spin up a
``ServerAsync`` subclass that needs to keep one TLS engine + EAP
fragmentation state machine per conversation. This module owns that
state machine and lets each scenario plug in its method-specific
behaviour via a small callback interface.

Production note: this is a **demo** scaffold, not a hardened EAP
server. Real deployments handle session expiry, identity caching,
the full menagerie of inner methods, and rotate per-conversation
crypto state across worker processes. The demos sidestep all of that
to keep the runnable scripts readable end-to-end.
"""

from __future__ import annotations

import secrets
import ssl
from typing import Callable

from pyrad2.eap._tls_eap import (
    FLAG_START,
    build_eap_tls_response,
    fragment_outbound,
    join_eap_message_avps,
    parse_eap_tls_request,
    split_into_eap_message_avps,
)

# RADIUS attribute codes the demo handler reads / writes directly.
EAP_MESSAGE = 79
STATE = 24

# Callback signature for the per-method post-handshake behaviour.
# Receives ``(decrypted_plaintext, write_response)`` where
# ``write_response`` is called by the handler to enqueue an encrypted
# reply to send back through the tunnel. The callback returns ``True``
# the moment it considers the conversation complete (server should
# emit Access-Accept), ``False`` otherwise.
InnerHandler = Callable[[bytes, Callable[[bytes], None]], bool]


class TlsEapServerSession:
    """One TLS-EAP conversation's worth of state for the demo servers.

    The supplicant drives the EAP loop via UDP RADIUS rounds; the
    scenario's ServerAsync subclass keeps an instance of this class
    per outstanding State cookie and dispatches each Access-Request to
    :meth:`handle_eap_response`. The session returns the next
    EAP-Request bytes to wrap in an Access-Challenge — or ``None``
    when the conversation is over and the server should send
    Access-Accept.

    Inner-exchange behaviour (PEAP's inner EAP dispatch, TTLS's inner
    AVP decode) plugs in via the ``inner_handler`` callback. EAP-TLS
    passes ``None`` here — there's no inner exchange.
    """

    def __init__(
        self,
        server_cert: str,
        server_key: str,
        eap_type: int,
        ca_cert: str | None = None,
        require_client_cert: bool = True,
        inner_handler: InnerHandler | None = None,
        first_inner_payload: bytes | None = None,
    ) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
        if require_client_cert:
            if ca_cert is None:
                raise ValueError(
                    "require_client_cert=True needs ca_cert for verification"
                )
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=ca_cert)
        else:
            ctx.verify_mode = ssl.CERT_NONE

        self._inbound = ssl.MemoryBIO()
        self._outbound = ssl.MemoryBIO()
        self._sslobj: ssl.SSLObject = ctx.wrap_bio(
            self._inbound, self._outbound, server_side=True
        )

        self._eap_type = eap_type
        self._eap_id = 0
        self._inbound_fragments: list[bytes] = []
        self._outbound_queue: list[tuple[int, bytes, int | None]] = []
        self._inner_handler = inner_handler
        # First payload PEAP servers push after handshake (typically
        # an EAP-Request/Identity). EAP-TLS leaves this ``None``; TTLS
        # leaves it ``None`` because the supplicant sends inner AVPs
        # unprompted.
        self._first_inner_payload = first_inner_payload
        self._first_inner_sent = False

        self.handshake_done = False
        self.complete = False

    def _next_eap_id(self) -> int:
        self._eap_id = (self._eap_id + 1) % 256
        return self._eap_id

    def start_request_bytes(self) -> bytes:
        """Build the opening server EAP-Request (S=1, body empty).

        Caller wraps this in an Access-Challenge with a fresh State
        cookie. The supplicant's reply triggers
        :meth:`handle_eap_response`.
        """
        # build_eap_tls_response always emits an EAP-Response code (2);
        # flip the first byte to EAP-Request (1) for the server side.
        body = build_eap_tls_response(
            eap_id=self._next_eap_id(),
            eap_type=self._eap_type,
            flags=FLAG_START,
            tls_bytes=b"",
        )
        return bytes([1]) + body[1:]

    def handle_eap_response(self, eap_payload: bytes) -> bytes | None:
        """Process one supplicant EAP-Response.

        Returns the next EAP-Request bytes to wrap in an Access-
        Challenge, or ``None`` when the conversation is complete and
        the server should emit Access-Accept (``self.complete``
        becomes ``True`` in the same call).
        """
        _eap_id, eap_type, flags, body = parse_eap_tls_request(eap_payload)
        if eap_type != self._eap_type:
            raise ValueError(
                f"Server session got EAP-Type {eap_type}, expected {self._eap_type}"
            )

        self._inbound_fragments.append(body)
        if flags & 0x40:  # M (More)
            # Mid-fragment ACK — empty-body EAP-Request, no flags.
            return self._build_request(flags=0, body=b"", total_length=None)

        joined = b"".join(self._inbound_fragments)
        self._inbound_fragments.clear()
        if joined:
            self._inbound.write(joined)

        try:
            self._sslobj.do_handshake()
            self.handshake_done = True
        except ssl.SSLWantReadError:
            pass

        # Post-handshake inner exchange.
        if self.handshake_done and self._inner_handler is not None:
            self._pump_inner()
        elif self.handshake_done and self._inner_handler is None:
            # EAP-TLS path: handshake completion alone marks the
            # conversation done. Drain any final handshake bytes the
            # server still owes (server Finished), and once those are
            # delivered we're free to emit Access-Accept.
            pass

        # Drain outbound TLS bytes into the fragmentation queue.
        if not self._outbound_queue:
            pending = self._outbound.read()
            if pending:
                self._outbound_queue = fragment_outbound(pending)

        if self._outbound_queue:
            flags_out, chunk, total_length = self._outbound_queue.pop(0)
            return self._build_request(flags_out, chunk, total_length)

        # Nothing left to send. For EAP-TLS that means the handshake
        # is fully drained; for PEAP/TTLS the inner handler decides.
        if self._inner_handler is None and self.handshake_done:
            self.complete = True
            return None
        if self.complete:
            return None
        # Otherwise emit an ACK and wait for the next supplicant frame.
        return self._build_request(flags=0, body=b"", total_length=None)

    def _pump_inner(self) -> None:
        """Drive one step of the post-handshake inner exchange."""
        try:
            decrypted = self._sslobj.read(16384)
        except ssl.SSLWantReadError:
            decrypted = b""

        def write_response(payload: bytes) -> None:
            self._sslobj.write(payload)

        # First post-handshake round: if the method has an opening
        # inner payload (PEAP's EAP-Request/Identity), push it now.
        if not self._first_inner_sent and self._first_inner_payload is not None:
            self._sslobj.write(self._first_inner_payload)
            self._first_inner_sent = True
            # Don't return — the supplicant may have piggybacked the
            # inner AVP push (TTLS) in the same record, in which case
            # the handler should still get a crack at it.

        if decrypted:
            done = self._inner_handler(decrypted, write_response)  # type: ignore[misc]
            if done:
                self.complete = True

    def _build_request(
        self,
        flags: int,
        body: bytes,
        total_length: int | None,
    ) -> bytes:
        eap = build_eap_tls_response(
            eap_id=self._next_eap_id(),
            eap_type=self._eap_type,
            flags=flags,
            tls_bytes=body,
            total_length=total_length,
        )
        return bytes([1]) + eap[1:]


def fresh_state_cookie() -> bytes:
    """16-byte cryptographically random State cookie for session keying."""
    return secrets.token_bytes(16)


def joined_eap_message(pkt) -> bytes:
    """Pull every EAP-Message AVP off an inbound packet and concatenate."""
    values = pkt[EAP_MESSAGE]
    out: list[bytes] = []
    for v in values:
        out.append(v if isinstance(v, bytes) else bytes.fromhex(v))
    return join_eap_message_avps(out)


def split_eap_message_for_reply(eap_packet: bytes) -> list[bytes]:
    """Mirror of :func:`pyrad2.eap._tls_eap.split_into_eap_message_avps`."""
    return split_into_eap_message_avps(eap_packet)
