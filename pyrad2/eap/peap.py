"""PEAPv0 (draft-josefsson-pppext-eap-tls-eap) — Protected EAP.

PEAP is structurally EAP-TLS with one extra layer: after the TLS
handshake completes the server tunnels a second, full EAP exchange
*inside* TLS application records. The inner exchange typically runs
EAP-MSCHAPv2 or EAP-GTC — methods that would be eavesdropping
targets in the clear but become safe inside the tunnel.

Conversation shape::

    1. Client → Server   EAP-Response/Identity (outer, usually anonymous)
    2. Server → Client   EAP-Request/PEAP, S=1
    3. ... TLS handshake (identical to EAP-TLS) ...
    4. Server → Client   EAP-Request/PEAP, encrypted EAP-Request/Identity
    5. Client → Server   EAP-Response/PEAP, encrypted EAP-Response/Identity
    6. Server → Client   EAP-Request/PEAP, encrypted EAP-Request/<inner method>
    7. ... inner method round-trips, every payload encrypted with TLS ...
    8. Server → Client   EAP-Request/PEAP, encrypted PEAP Result-TLV (success)
    9. Client → Server   EAP-Response/PEAP, encrypted PEAP Result-TLV (echo)
   10. Server → Client   EAP-Success (outer, not encrypted)

PEAPv0 differs from PEAPv2 (rarely deployed) in not doing
cryptobinding; the Result-TLV at step 8 carries the success
indication directly. This module implements v0.

Client cert is **not** required — PEAP authenticates only the server's
cert during TLS, with the inner method authenticating the user. EAP-TLS
demands mutual cert auth; PEAP relaxes that, which is the whole point.
"""

from __future__ import annotations

import ssl
import struct
from typing import TYPE_CHECKING, Any, cast

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
from pyrad2.eap.base import EapMethod, MethodFactory

if TYPE_CHECKING:
    from pyrad2.packet import AuthPacket, Packet

# IANA / draft assignment.
EAP_TYPE_PEAP = 25

# PEAPv0 Result-TLV (draft-josefsson §2.3) marks the end of the inner
# exchange. The TLV body is 11 bytes: 2-byte type (0x80 0x03 — Result
# with M bit), 2-byte length (0x00 0x02), 2-byte status (1=Success,
# 2=Failure). The inner EAP wrapper around the TLV adds 5 bytes:
# code(1) id(1) length(2) type=33(1).
PEAP_TLV_TYPE = 33  # EAP-Type for "PEAP TLV / Extensions"
PEAP_TLV_RESULT = 0x8003
PEAP_TLV_STATUS_SUCCESS = 1
PEAP_TLV_STATUS_FAILURE = 2


def _build_inner_eap_identity(eap_id: int, identity: bytes) -> bytes:
    """Pack an inner EAP-Response/Identity to send back through the tunnel."""
    length = 5 + len(identity)
    return (
        bytes([EAPPacketType.RESPONSE, eap_id])
        + length.to_bytes(2, "big")
        + bytes([EAPType.IDENTITY])
        + identity
    )


def _build_peap_tlv_result_response(eap_id: int, status: int) -> bytes:
    """Build the inner EAP-Response that echoes back a Result-TLV.

    Wire shape (draft-josefsson §2.3)::

        EAP header: code=2, id, length(2), type=33
        TLV: type=0x8003 (Result, M bit set), length=2, status(2)

    Total length = 5 + 6 = 11 bytes.
    """
    return struct.pack(
        "!BBHB HH H",
        EAPPacketType.RESPONSE,
        eap_id,
        11,
        PEAP_TLV_TYPE,
        PEAP_TLV_RESULT,
        2,
        status,
    )


class PeapMethod(EapMethod):
    """PEAPv0 supplicant driver.

    One instance per conversation. The TLS engine and the inner
    method's state both live on the instance; the EAP registry hands
    out fresh instances via the factory passed to ``register_method``.

    Inner method selection: either pass ``inner_method`` (a registered
    EAP method name like ``"eap-mschapv2"``) or ``inner_method_factory``
    (a zero-argument callable returning an ``EapMethod`` — useful for
    tests injecting a fake). When neither is given the method raises
    on the first inner EAP-Request, before any credential leaks.

    The outer EAP-Identity is sent in cleartext (it's outside TLS) and
    defaults to the bytes ``b"anonymous"`` so the real username — which
    PEAP exists to protect — stays inside the tunnel. The inner
    Identity is the real ``User-Name``, sent only after the handshake.
    """

    def __init__(
        self,
        ca_cert: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
        outer_identity: bytes = b"anonymous",
        inner_method: str | None = None,
        inner_method_factory: MethodFactory | None = None,
    ) -> None:
        if ssl_context is None:
            ssl_context = make_client_tls_context(
                ca_cert=ca_cert,
                client_cert=client_cert,
                client_key=client_key,
            )
        self._engine = TlsEapEngine(ssl_context)
        self._outbound_queue: list[tuple[int, bytes, int | None]] = []
        self._outer_identity = outer_identity
        self._inner_method_name = inner_method
        self._inner_method_factory = inner_method_factory
        # Inner method instantiated on first inner EAP-Request that
        # isn't an Identity (PEAP itself handles Identity).
        self._inner_method: EapMethod | None = None
        # Once inner_method.start has been called, we don't call it
        # again across the rest of the conversation.
        self._inner_method_started = False

    def start(self, pkt: "AuthPacket") -> None:
        identity = self._outer_identity
        eap_identity = _build_inner_eap_identity(eap_id=0, identity=identity)
        # Outer identity gets a fresh EAP id when the client sends the
        # very first Access-Request; we leave id=0 here for simplicity
        # since the server doesn't check it on the Identity round.
        pkt[EAP_MESSAGE_ATTR] = split_into_eap_message_avps(eap_identity)

    def respond(self, pkt: "AuthPacket", challenge: "Packet") -> None:
        eap_payload = join_eap_message_avps(challenge[EAP_MESSAGE_ATTR])
        eap_id, eap_type, flags, body = parse_eap_tls_request(eap_payload)

        if eap_type != EAP_TYPE_PEAP:
            raise ValueError(
                f"Expected EAP-Type {EAP_TYPE_PEAP} (PEAP), got {eap_type}"
            )

        if flags & FLAG_START:
            self._engine.advance_handshake()
        else:
            # Mid-handshake the body is a TLS record; post-handshake
            # it's an encrypted EAP-Request. The engine demuxes by
            # internal state — write to inbound BIO regardless.
            self._engine.feed(body)
            if not self._engine.handshake_done:
                self._engine.advance_handshake()

        # Post-handshake path: if we just finished the TLS handshake
        # *and* the server piggybacked an inner EAP-Request in the
        # same record, decrypt and handle it now.
        if self._engine.handshake_done and body:
            inner_request = self._engine.read_plaintext()
            if inner_request:
                inner_response = self._handle_inner_eap(inner_request, pkt)
                if inner_response is not None:
                    self._engine.write_plaintext(inner_response)

        # Drain any queued outbound TLS bytes (handshake records or
        # the encrypted inner EAP response we just wrote).
        tls_out = self._engine.pending_outbound()
        if tls_out and not self._outbound_queue:
            self._outbound_queue = fragment_outbound(tls_out)

        if self._outbound_queue:
            flags_out, chunk, total_length = self._outbound_queue.pop(0)
        else:
            # Nothing to send back: empty EAP-Response acknowledges
            # either a mid-fragmentation ACK or the server's final
            # handshake message (RFC 5216 §2.1.5).
            flags_out, chunk, total_length = 0, b"", None

        response = build_eap_tls_response(
            eap_id=eap_id,
            eap_type=EAP_TYPE_PEAP,
            flags=flags_out,
            tls_bytes=chunk,
            total_length=total_length,
        )
        pkt[EAP_MESSAGE_ATTR] = split_into_eap_message_avps(response)
        pkt[STATE_ATTR] = challenge[STATE_ATTR]

    def _handle_inner_eap(
        self, inner_request: bytes, outer_pkt: "AuthPacket"
    ) -> bytes | None:
        """Drive one round of the *inner* EAP exchange.

        The server may pack multiple inner EAP messages into one TLS
        record but in practice it's one Request per round. We parse
        the EAP header and dispatch on the type:

        * EAP-Type=Identity → reply with the real ``User-Name``
        * EAP-Type=PEAP-TLV (33) → echo the Result-TLV back
        * Anything else → delegate to the configured inner method
        """
        if len(inner_request) < 5:
            raise ValueError(f"Inner EAP request truncated: {len(inner_request)} bytes")
        code = inner_request[0]
        eap_id = inner_request[1]
        eap_type = inner_request[4]

        if code != EAPPacketType.REQUEST:
            # Unexpected — the inner side only sends Requests at us.
            raise ValueError(
                f"Inner EAP code {code} is not a Request — server protocol violation"
            )

        if eap_type == EAPType.IDENTITY:
            identity = self._real_identity_from_packet(outer_pkt)
            return _build_inner_eap_identity(eap_id, identity)

        if eap_type == PEAP_TLV_TYPE:
            # Result-TLV from the server — echo it back so the server
            # can move to outer EAP-Success.
            status = self._parse_peap_tlv_status(inner_request)
            return _build_peap_tlv_result_response(eap_id, status)

        # Delegate to the inner EAP method.
        return self._delegate_to_inner_method(inner_request, outer_pkt)

    def _delegate_to_inner_method(
        self, inner_request: bytes, outer_pkt: "AuthPacket"
    ) -> bytes:
        """Hand the inner EAP-Request to the configured inner method.

        We build a synthetic dict-shaped packet that mirrors the
        shape ``EapMethod`` instances expect (``__getitem__`` /
        ``__setitem__`` over ``EAP_MESSAGE_ATTR`` and ``STATE_ATTR``,
        plus the User-Name / User-Password keys for credential
        bootstrap). The inner method writes its response into the
        synthetic packet; we extract and return the bytes.
        """
        inner_method = self._ensure_inner_method()
        synth_outgoing = _SyntheticInnerPacket()
        # Mirror credentials so the inner method's start/respond can
        # pull User-Name and User-Password out of the same shape it
        # would on the outer packet.
        for key in (1, "User-Name", 2, "User-Password"):
            try:
                if key in outer_pkt:
                    synth_outgoing[key] = outer_pkt[key]
            except (TypeError, KeyError):
                # FakeAuthPacket only supports int keys; outer Packet
                # supports strings too. Either failure mode is fine.
                pass

        # ``EapMethod.start`` / ``respond`` are typed as ``AuthPacket`` /
        # ``Packet`` because that's their production shape, but they
        # only ever use the dict protocol on the argument. The
        # synthetic packet provides exactly that shape; cast through
        # ``Any`` rather than threading a protocol type through the
        # public ABC.
        synth_out_any = cast(Any, synth_outgoing)

        if not self._inner_method_started:
            # start() populates the method's internal credential state
            # (MSCHAPv2 stashes user_name + password here). We discard
            # the EAP-Message it writes — PEAP already sent Identity.
            inner_method.start(synth_out_any)
            self._inner_method_started = True

        synth_challenge = _SyntheticInnerPacket()
        synth_challenge[EAP_MESSAGE_ATTR] = [inner_request]
        # Inner methods carry State via the outer EAP envelope, but
        # they unconditionally read challenge[STATE_ATTR] today —
        # supply an empty list so the assignment in respond() doesn't
        # KeyError. We immediately overwrite synth_outgoing[STATE_ATTR]
        # below so nothing leaks.
        synth_challenge[STATE_ATTR] = [b""]

        inner_method.respond(synth_out_any, cast(Any, synth_challenge))

        avps = synth_outgoing[EAP_MESSAGE_ATTR]
        # Inner methods write a single-element list; join defensively
        # in case a method ever pre-splits.
        return b"".join(avps)

    def _ensure_inner_method(self) -> EapMethod:
        """Return the inner method, instantiating on first use.

        Resolved late because the inner method's constructor may have
        side effects (state allocation for stateful methods) and we
        want to defer those until we actually need them.
        """
        if self._inner_method is not None:
            return self._inner_method
        if self._inner_method_factory is not None:
            self._inner_method = self._inner_method_factory()
            return self._inner_method
        if self._inner_method_name is not None:
            # Resolve through the registry. Local import dodges the
            # cycle: pyrad2.eap.__init__ imports this module.
            from pyrad2.eap.base import get_method

            resolved = get_method(self._inner_method_name)
            if resolved is None:
                raise ValueError(
                    f"PEAP inner method '{self._inner_method_name}' is not registered"
                )
            self._inner_method = resolved
            return self._inner_method
        raise ValueError(
            "PEAP needs an inner_method name or inner_method_factory; "
            "got neither and the server expects an inner EAP exchange"
        )

    @staticmethod
    def _parse_peap_tlv_status(eap_packet: bytes) -> int:
        """Pull the status code out of an inbound PEAP Result-TLV.

        The TLV starts 5 bytes in (after the EAP header). Its first
        two bytes are the TLV type (0x80 + reserved bits), then the
        2-byte length, then the 2-byte status. We just echo whatever
        the server sent; if it was Success we're done, if it was
        Failure the server will follow with outer EAP-Failure.
        """
        if len(eap_packet) < 5 + 6:
            return PEAP_TLV_STATUS_FAILURE
        return struct.unpack("!H", eap_packet[9:11])[0]

    @staticmethod
    def _real_identity_from_packet(pkt: "AuthPacket") -> bytes:
        """Real (inner) identity is the outer packet's User-Name.

        Falls back to ``b"anonymous"`` only so the inner side has
        *something* to respond with even when the caller forgot — a
        degenerate but well-formed exchange that the server will
        Reject.
        """
        for key in (1, "User-Name"):
            try:
                if key in pkt:
                    raw = pkt[key][0]
                    return raw.encode("utf-8") if isinstance(raw, str) else raw
            except (TypeError, KeyError):
                continue
        return b"anonymous"


class _SyntheticInnerPacket:
    """Dict-shaped stand-in for AuthPacket used to drive inner methods.

    The inner ``EapMethod`` implementations only need the dict
    behaviours on the synthetic packet — they index by 79
    (EAP-Message) and 24 (State), and read 1 / "User-Name" /
    2 / "User-Password" off the credentials. The full ``Packet``
    machinery (dictionary lookup, wire codec, authenticator) is
    intentionally absent.

    Value typing is ``Any`` because the synthetic packet mirrors
    whatever the outer packet stored — a real ``AuthPacket`` exposes
    attribute values as lists but ``FakeAuthPacket`` (test) and the
    odd custom subclass may use other containers, and the inner
    method only cares about ``[0]``-indexable shapes.
    """

    def __init__(self) -> None:
        self._store: dict[int | str, Any] = {}

    def __contains__(self, key: int | str) -> bool:
        return key in self._store

    def __getitem__(self, key: int | str) -> Any:
        return self._store[key]

    def __setitem__(self, key: int | str, value: Any) -> None:
        self._store[key] = value
