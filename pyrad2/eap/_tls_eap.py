"""Shared TLS-EAP framing for EAP-TLS, PEAP, and EAP-TTLS.

EAP-TLS (RFC 5216), PEAP (draft-josefsson-pppext-eap-tls-eap), and
EAP-TTLS (RFC 5281) all sit on the same wire shape: an EAP envelope
carrying a TLS handshake (and, for PEAP/TTLS, inner data after the
handshake) split across as many EAP-Request/Response round-trips as
fragmentation demands. This module owns that shape so each method only
implements its own start/inner behaviour.

Wire layout per RFC 5216 §3.1::

    code(1) | id(1) | length(2) | type(1) | flags(1)
            | [TLS Message Length(4) — present iff L=1]
            | TLS data(N)

Flags byte:

* ``L`` (0x80) — Length included (first fragment of a multi-fragment msg)
* ``M`` (0x40) — More fragments to come
* ``S`` (0x20) — Start (server's opening request only)

The receiver accumulates fragments until ``M=0`` and then hands the
joined TLS bytes to the in-memory ``SSLObject``. The sender splits
outbound TLS bytes into MTU-sized chunks, setting ``M=1`` on every
fragment except the last and ``L`` + length header on the first.

This module is private (leading underscore) — methods import the
helpers they need; nothing here is part of the public API.
"""

from __future__ import annotations

import ssl
import struct
from typing import Iterable

# RFC 5216 §3.1 / RFC 5281 §9.1 / draft-josefsson §3.1 — Flags byte bits.
FLAG_LENGTH = 0x80
FLAG_MORE = 0x40
FLAG_START = 0x20

# Per-fragment ceiling on the TLS bytes we pack into a single
# EAP-Response. The RADIUS AVP value field maxes at 253 bytes; an
# EAP-Message AVP is repeated and joined by the receiver per RFC 3579
# §3.1, but the bundled pyrad2 dictionaries don't mark code 79 as
# ``concat`` so the safe thing is to keep each individual EAP packet
# inside one AVP. 5 bytes go to the EAP header, 1 to the flags byte,
# and 4 to the optional Length header (only on the first fragment of a
# multi-fragment message); we round down to 240 as a comfortable
# common payload budget that leaves room for an L-bearing first
# fragment without splitting the EAP header itself.
DEFAULT_FRAGMENT_PAYLOAD = 240

# EAP-Message attribute code (RFC 2869 §5.13) and State (RFC 2865 §5.24).
EAP_MESSAGE_ATTR = 79
STATE_ATTR = 24


def parse_eap_tls_request(eap_payload: bytes) -> tuple[int, int, int, bytes]:
    """Parse an inbound EAP-Request carrying a TLS-EAP method.

    Returns a 4-tuple ``(eap_id, eap_type, flags, body)`` where
    ``body`` is the bytes following the flags byte and the optional
    Length header (i.e. the raw TLS fragment for this round). The
    Length header, when present, is consumed but not exposed — only
    multi-fragment reassembly callers care, and they track expected
    totals themselves.

    Raises ``ValueError`` if the payload is shorter than the minimum
    6-byte EAP+flags shape required by RFC 5216 §3.1.
    """
    if len(eap_payload) < 6:
        raise ValueError(
            f"EAP-TLS payload truncated: got {len(eap_payload)} bytes, "
            "need at least 6 (code+id+length+type+flags)"
        )
    eap_id = eap_payload[1]
    eap_type = eap_payload[4]
    flags = eap_payload[5]
    cursor = 6
    if flags & FLAG_LENGTH:
        # First fragment of a multi-fragment message: the next four
        # bytes are the total TLS message length. We don't need the
        # value for single-pass reassembly (we trust the M bit), but
        # we must skip past it to reach the TLS bytes.
        if len(eap_payload) < cursor + 4:
            raise ValueError(
                "EAP-TLS first-fragment Length header truncated: "
                f"got {len(eap_payload)} bytes, need at least {cursor + 4}"
            )
        cursor += 4
    body = eap_payload[cursor:]
    return eap_id, eap_type, flags, body


def build_eap_tls_response(
    eap_id: int,
    eap_type: int,
    flags: int,
    tls_bytes: bytes,
    total_length: int | None = None,
) -> bytes:
    """Build a single EAP-Response packet for a TLS-EAP method.

    ``flags`` carries the L/M/S/reserved bits per RFC 5216 §3.1.
    ``total_length`` is required when ``L=1`` (first fragment of a
    multi-fragment message) and ignored otherwise.

    Callers handling the fragmentation loop pass the right ``flags``
    and ``tls_bytes`` for each round; this helper only does the
    byte-level packing.
    """
    body = bytes(tls_bytes)
    if flags & FLAG_LENGTH:
        if total_length is None:
            raise ValueError("EAP-TLS L flag set but no total_length supplied")
        length_header = struct.pack("!I", total_length)
    else:
        length_header = b""

    eap_length = 5 + 1 + len(length_header) + len(body)
    header = struct.pack(
        "!BBHBB",
        2,  # EAPPacketType.RESPONSE
        eap_id,
        eap_length,
        eap_type,
        flags,
    )
    return header + length_header + body


def fragment_outbound(
    tls_bytes: bytes,
    fragment_size: int = DEFAULT_FRAGMENT_PAYLOAD,
) -> list[tuple[int, bytes, int | None]]:
    """Split outbound TLS bytes into one or more EAP-TLS fragments.

    Returns a list of ``(flags, body, total_length)`` triples in send
    order. Length header is emitted only on the first fragment of a
    multi-fragment message (L+M on the first, M on middles, neither on
    the last). A single-fragment message yields one triple with
    ``flags=0`` and ``total_length=None``.

    ``fragment_size`` is the *payload* budget per fragment — the
    caller's MTU minus the EAP+flags header — so first-fragment Length
    headers don't affect downstream chunk boundaries.
    """
    total = len(tls_bytes)
    if total <= fragment_size:
        return [(0, tls_bytes, None)]

    chunks: list[tuple[int, bytes, int | None]] = []
    cursor = 0
    first = True
    while cursor < total:
        end = min(cursor + fragment_size, total)
        chunk = tls_bytes[cursor:end]
        is_last = end == total
        flags = 0
        length: int | None = None
        if first:
            flags |= FLAG_LENGTH
            length = total
            first = False
        if not is_last:
            flags |= FLAG_MORE
        chunks.append((flags, chunk, length))
        cursor = end
    return chunks


def reassemble_inbound(
    fragments: Iterable[tuple[int, bytes]],
) -> bytes:
    """Concatenate a sequence of inbound TLS-EAP fragments into one body.

    ``fragments`` is iterated in receive order — each entry is
    ``(flags, body)`` from :func:`parse_eap_tls_request`. This helper
    is a thin wrapper over ``b"".join`` exposed as a named function so
    callers reading the code can see the reassembly point in the
    state machine.
    """
    return b"".join(body for _, body in fragments)


def split_into_eap_message_avps(
    eap_packet: bytes,
    avp_max: int = 253,
) -> list[bytes]:
    """Split a single EAP packet across one or more EAP-Message AVPs.

    A RADIUS attribute's value field is capped at 253 bytes (RFC 2865
    §5). RFC 3579 §3.1 lets a single EAP message exceed that by being
    repeated across multiple EAP-Message AVPs which the receiver
    concatenates. pyrad2's bundled dictionaries don't currently mark
    code 79 as ``concat``, so the simpler thing for a method to do is
    write the AVP list itself: ``pkt[79] = split_into_eap_message_avps(...)``.

    Returns at least one bytes value; if the EAP packet already fits
    in one AVP, the list has length 1.
    """
    if len(eap_packet) <= avp_max:
        return [eap_packet]
    return [eap_packet[i : i + avp_max] for i in range(0, len(eap_packet), avp_max)]


def join_eap_message_avps(values: Iterable[bytes]) -> bytes:
    """Concatenate the EAP-Message AVP list back into one EAP packet.

    The inverse of :func:`split_into_eap_message_avps`. Used by every
    TLS-EAP method to materialise the inbound EAP-Request before
    handing it to :func:`parse_eap_tls_request`.
    """
    return b"".join(values)


def make_client_tls_context(
    ca_cert: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    minimum_tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
) -> ssl.SSLContext:
    """Build an SSLContext for the supplicant side of an EAP-TLS exchange.

    PEAP and TTLS use the same shape — only the inner method differs —
    so this is the one knob every TLS-EAP method shares.

    Defaults:
    * Minimum TLS 1.2 (RFC 5216 §2.2 mandates >= 1.0; we match what
      RFC 9325 §4 recommends as the floor for any new TLS deployment).
    * Server certificate is always validated. ``ca_cert`` points at
      the AAA server's trust anchor (typically the enterprise CA
      under whose chain the RADIUS server's cert was issued); when
      omitted, the system trust store is used. The API deliberately
      does **not** expose a "skip verification" toggle — an
      unverified TLS handshake is a MITM-trivial channel and there is
      no production EAP-TLS deployment that should land on that path.
      Test harnesses must generate their own CA and pass it explicitly
      via ``ca_cert``.
    * Client certificate (mutual auth) loaded only when both
      ``client_cert`` and ``client_key`` are provided. EAP-TLS requires
      this; PEAP / TTLS leave it optional.

    Hostname verification is off because EAP-TLS speaks over EAP, not
    over a TCP socket to a named host — the server identity is
    asserted by the cert chain + ``ca_cert`` trust anchor alone.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = minimum_tls_version
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    if ca_cert is not None:
        ctx.load_verify_locations(cafile=ca_cert)
    else:
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    if client_cert is not None and client_key is not None:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return ctx


class TlsEapEngine:
    """Memory-BIO TLS engine wrapped for use inside an EAP method.

    Each EAP-TLS / PEAP / TTLS conversation owns one engine instance.
    The method's ``respond`` hook calls :meth:`feed` with the joined
    inbound TLS bytes (assembled across however many fragments the
    server sent), then :meth:`pending_outbound` to drain the bytes the
    TLS stack wants to send next. Application-data writes (PEAP inner
    EAP, TTLS inner AVPs) go through :meth:`write_plaintext` /
    :meth:`read_plaintext` once :attr:`handshake_done` is true.
    """

    def __init__(self, context: ssl.SSLContext) -> None:
        # MemoryBIO pair: ``_inbound`` is what the TLS stack reads,
        # ``_outbound`` is what it writes. We never wrap a real
        # socket; the EAP layer is the transport.
        self._inbound = ssl.MemoryBIO()
        self._outbound = ssl.MemoryBIO()
        # ``server_hostname`` is irrelevant (hostname check is off) but
        # ``SSLContext.wrap_bio`` requires *something* for a client
        # context. The string is never sent — SNI gets included in the
        # handshake but EAP-TLS servers ignore it.
        self._sslobj: ssl.SSLObject = context.wrap_bio(
            self._inbound,
            self._outbound,
            server_hostname="eap-tls",
        )
        self.handshake_done: bool = False

    def feed(self, tls_bytes: bytes) -> None:
        """Push inbound TLS bytes into the engine.

        Always followed by either :meth:`advance_handshake` (during
        the handshake) or :meth:`read_plaintext` (post-handshake) to
        drive the state machine forward.
        """
        if tls_bytes:
            self._inbound.write(tls_bytes)

    def advance_handshake(self) -> None:
        """Run one handshake step.

        Catches ``SSLWantReadError`` because in memory-BIO mode that's
        the normal "I need more bytes" signal — the EAP layer will
        carry them on the next round. Any other ``SSLError`` is fatal
        and propagates so the caller can surface the auth failure.
        """
        try:
            self._sslobj.do_handshake()
            self.handshake_done = True
        except ssl.SSLWantReadError:
            # Expected. More bytes will arrive on the next EAP round.
            return

    def pending_outbound(self) -> bytes:
        """Return any bytes the TLS stack queued for the peer.

        Returns an empty ``bytes`` when there's nothing to send —
        which, mid-handshake, is the signal that we're done and the
        next outbound EAP message should be an empty-payload ACK
        (RFC 5216 §2.1.5).
        """
        return self._outbound.read()

    def write_plaintext(self, data: bytes) -> None:
        """Encrypt application data for transmission to the peer.

        Used after the handshake completes for PEAP inner EAP messages
        and TTLS inner AVPs. The resulting ciphertext is pulled out
        with :meth:`pending_outbound` immediately after.
        """
        self._sslobj.write(data)

    def read_plaintext(self) -> bytes:
        """Decrypt all pending application data from the peer.

        Drains in a loop because ``SSLObject.read`` returns one record
        at a time. Returns an empty ``bytes`` when there's nothing
        decrypted — usually because the peer hasn't sent a full record
        yet and the next EAP round will deliver more.
        """
        out: list[bytes] = []
        while True:
            try:
                chunk = self._sslobj.read(16384)
            except ssl.SSLWantReadError:
                break
            if not chunk:
                break
            out.append(chunk)
        return b"".join(out)
