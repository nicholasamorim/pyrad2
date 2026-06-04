"""EAP-TLS (RFC 5216) — certificate-based mutual authentication.

EAP-TLS is the strongest of the production EAP methods: both ends
present X.509 certificates and the EAP session reduces to running a
TLS handshake to completion over EAP-Message framing. There is no
password, no shared secret, and no inner method — if the handshake
succeeds, the server returns ``Access-Accept`` and the EAP session is
done.

Conversation shape (RFC 5216 §2.1)::

    1. Client → Server   Access-Request / EAP-Response/Identity
    2. Server → Client   Access-Challenge / EAP-Request/EAP-TLS, S=1
    3. Client → Server   EAP-Response/EAP-TLS, ClientHello
    4. Server → Client   EAP-Request/EAP-TLS, ServerHello..ServerHelloDone
                         (typically fragmented across several rounds)
    5. Client → Server   EAP-Response/EAP-TLS, Certificate, ClientKeyExchange,
                         CertificateVerify, ChangeCipherSpec, Finished
    6. Server → Client   EAP-Request/EAP-TLS, ChangeCipherSpec, Finished
    7. Client → Server   EAP-Response/EAP-TLS, *empty* (RFC 5216 §2.1.5)
    8. Server → Client   Access-Accept (+ MS-MPPE-Send/Recv-Key)

This module implements steps 3, 5, and 7 — every step that needs the
TLS state machine. The fragmentation arithmetic, the MemoryBIO
plumbing, and the EAP-TLS flags byte all live in
:mod:`pyrad2.eap._tls_eap` so PEAP and EAP-TTLS share them verbatim.

MSK derivation — turning the TLS master secret into the MS-MPPE-Send
/ Recv keys the server packs into the final Access-Accept — is the
**server's** responsibility, not the supplicant's. pyrad2's role here
is the supplicant; we drive the handshake and read the resulting
Accept, no key export needed.
"""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

from pyrad2.constants import EAPPacketType, EAPType
from pyrad2.eap._tls_eap import (
    EAP_MESSAGE_ATTR,
    STATE_ATTR,
    FLAG_START,
    TlsEapEngine,
    build_eap_tls_response,
    fragment_outbound,
    join_eap_message_avps,
    make_client_tls_context,
    parse_eap_tls_request,
    split_into_eap_message_avps,
)
from pyrad2.eap.base import EapMethod

if TYPE_CHECKING:
    from pyrad2.packet import AuthPacket, Packet

# RFC 5216 §3.1 — EAP-TLS uses EAP-Type 13.
EAP_TYPE_TLS = 13

# Standard FreeRADIUS / hostapd dictionary spelling. Codes here match
# the EAPType enum but EAP-TLS isn't currently a member; the int is
# the on-wire byte we emit.


class TlsMethod(EapMethod):
    """EAP-TLS supplicant driver.

    A fresh ``TlsMethod`` is created per conversation by the registry;
    the per-conversation TLS engine, fragmentation buffer, and
    outbound queue live on the instance. The instance is **bound** to
    a single ``SSLContext`` — typically built via
    :func:`make_client_tls_context`. Tests substitute their own
    context to thread a generated CA into the trust store.

    The pattern is::

        from pyrad2.eap.tls import TlsMethod
        from pyrad2.eap import register_method

        register_method(
            "eap-tls",
            lambda: TlsMethod(
                ca_cert="/etc/pki/aaa-ca.pem",
                client_cert="/etc/pki/client.crt",
                client_key="/etc/pki/client.key",
            ),
        )

    Both ``ca_cert`` and the client cert/key pair are constructor
    args; this method has no use for ``User-Password`` so callers
    don't need to populate one on the outgoing packet.
    """

    def __init__(
        self,
        ca_cert: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
        identity: bytes | None = None,
    ) -> None:
        # ``ssl_context`` is the test-suite escape hatch: an already
        # configured context (including any trust-anchor injection)
        # bypasses the file-system load. Production callers pass file
        # paths and let make_client_tls_context do the build.
        if ssl_context is None:
            ssl_context = make_client_tls_context(
                ca_cert=ca_cert,
                client_cert=client_cert,
                client_key=client_key,
            )
        self._engine = TlsEapEngine(ssl_context)
        # Outbound fragment queue: when the TLS engine produces a
        # large flight (Certificate, ServerHelloDone et al on the
        # server side), we fragment_outbound once and serve one
        # fragment per server EAP-Request until drained.
        self._outbound_queue: list[tuple[int, bytes, int | None]] = []
        # Identity supplied separately because EAP-TLS doesn't use
        # User-Password and many supplicants send a "fake" outer
        # identity (e.g. ``anonymous`` or just the realm) to avoid
        # leaking the certificate's Common Name on the unencrypted
        # Access-Request.
        self._identity = identity

    def start(self, pkt: "AuthPacket") -> None:
        """Seed the first Access-Request with an EAP-Response/Identity.

        EAP-TLS *can't* carry the TLS ClientHello on the first round —
        per RFC 5216 §2.1 the server must first send EAP-Request/EAP-TLS
        with S=1 before the client says anything TLS. So step one is
        always the bare Identity response, and the TLS conversation
        starts on the first inbound challenge.
        """
        identity = self._identity or self._identity_from_packet(pkt)
        eap_identity = self._build_identity_response(identity)
        pkt[EAP_MESSAGE_ATTR] = split_into_eap_message_avps(eap_identity)

    def respond(self, pkt: "AuthPacket", challenge: "Packet") -> None:
        """Drive one round of the TLS handshake.

        The flow per round is:

        1. Reassemble the inbound EAP-Message AVPs into one EAP packet.
        2. Parse the EAP-TLS flags + body.
        3. Feed any TLS bytes into the engine and advance the handshake.
        4. Dequeue the next outbound fragment (or, if nothing remains
           to send and the handshake completed, emit an empty EAP-TLS
           response per RFC 5216 §2.1.5 to ACK the server's Finished).
        5. Carry the server's State across the round-trip.
        """
        eap_payload = join_eap_message_avps(challenge[EAP_MESSAGE_ATTR])
        eap_id, eap_type, flags, body = parse_eap_tls_request(eap_payload)

        if eap_type != EAP_TYPE_TLS:
            raise ValueError(
                f"Expected EAP-Type {EAP_TYPE_TLS} (EAP-TLS), got {eap_type}"
            )

        # The Start flag (S=1) signals the server opens the conversation
        # with an empty TLS body — we shouldn't feed those zero bytes
        # to the engine, just kick the handshake.
        if flags & FLAG_START:
            self._engine.advance_handshake()
        else:
            # Accumulate inbound TLS bytes regardless of fragmentation:
            # the TLS layer handles record boundaries; we only need to
            # respect the *EAP*-level fragmentation, which the
            # send-side fragment_outbound already linearises by the
            # time the server collapses them back into one logical
            # message.
            self._engine.feed(body)
            self._engine.advance_handshake()

        # Pull whatever the TLS stack queued for transmission. Empty
        # response is legitimate: it's how we ACK the server's final
        # Finished (RFC 5216 §2.1.5) and how mid-handshake gaps where
        # the server still owes us bytes get acknowledged.
        tls_out = self._engine.pending_outbound()
        if tls_out and not self._outbound_queue:
            self._outbound_queue = fragment_outbound(tls_out)

        if self._outbound_queue:
            flags_out, chunk, total_length = self._outbound_queue.pop(0)
        else:
            flags_out, chunk, total_length = 0, b"", None

        response = build_eap_tls_response(
            eap_id=eap_id,
            eap_type=EAP_TYPE_TLS,
            flags=flags_out,
            tls_bytes=chunk,
            total_length=total_length,
        )
        pkt[EAP_MESSAGE_ATTR] = split_into_eap_message_avps(response)
        # State always rides across an EAP challenge round.
        pkt[STATE_ATTR] = challenge[STATE_ATTR]

    @staticmethod
    def _identity_from_packet(pkt: "AuthPacket") -> bytes:
        """Pull the outer identity from the packet's User-Name.

        EAP-TLS authentication binds to the certificate, not the
        username — but the EAP-Response/Identity still carries
        *something*. We use ``User-Name`` if present, falling back to
        ``b"anonymous"`` so the framing always has a non-empty
        identity field.
        """
        if 1 in pkt:
            raw = pkt[1][0]
        elif "User-Name" in pkt:
            raw = pkt["User-Name"][0]
        else:
            return b"anonymous"
        return raw.encode("utf-8") if isinstance(raw, str) else raw

    @staticmethod
    def _build_identity_response(identity: bytes) -> bytes:
        """Pack ``identity`` into an EAP-Response/Identity packet.

        The same shape every other pyrad2 EAP method emits; reproduced
        locally to avoid pulling in the EAP-MD5 module just for one
        helper.
        """
        from pyrad2 import packet as _packet

        length = 5 + len(identity)
        return (
            bytes([EAPPacketType.RESPONSE, _packet.CURRENT_ID])
            + length.to_bytes(2, "big")
            + bytes([EAPType.IDENTITY])
            + identity
        )
