"""EAP-TTLS (RFC 5281) — Tunneled TLS Authentication Protocol.

EAP-TTLS shares the outer shape of EAP-TLS and PEAP: a TLS handshake
carried in EAP-Message AVPs across as many fragments as it takes. The
inner exchange, however, is **not** EAP — it's a stream of Diameter
AVPs (RFC 5281 §10) carrying whatever credential format the deployment
chose: PAP, CHAP, MS-CHAP, MS-CHAPv2, or another EAP method.

pyrad2's TTLS implementation ships PAP only out of the box. PAP is
both the simplest case (just two AVPs — User-Name and User-Password
in cleartext, with TLS providing the confidentiality) and far and
away the most common deployment shape — the canonical eduroam
configuration uses TTLS/PAP. Other inner methods can be added later
without touching the TLS-EAP framing.

Conversation shape::

    1. Client → Server   EAP-Response/Identity (outer, often anonymous)
    2. Server → Client   EAP-Request/EAP-TTLS, S=1
    3. ... TLS handshake (identical framing to EAP-TLS, server-only
       cert by default) ...
    4. Client → Server   EAP-Response/EAP-TTLS carrying TLS app data:
                         { User-Name AVP, User-Password AVP }
    5. Server → Client   EAP-Success (outer, not encrypted)

The supplicant pushes the credential AVPs unprompted — there is no
server-side inner request, so the post-handshake flow is much shorter
than PEAP's.

Diameter AVP wire format (RFC 6733 §4.1), as used by TTLS::

    AVP Code: 4 octets   - identifies the attribute. For RADIUS-derived
                           AVPs (User-Name=1, User-Password=2), the
                           code matches the RADIUS attribute number.
    AVP Flags: 1 octet   - V (Vendor) and M (Mandatory) bits. RADIUS
                           AVPs set M only (0x40); TTLS specifies that
                           User-Name and User-Password must have M set.
    AVP Length: 3 octets - total length including header, before
                           padding to a 4-byte boundary.
    Vendor-ID: 4 octets  - present only when V is set. Absent for the
                           plain RADIUS-derived attributes we use.
    Data: variable        - the value, padded with zero bytes to the
                           next 4-byte alignment.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pyrad2.eap._tls_eap import TlsEapMethodBase

if TYPE_CHECKING:
    from pyrad2.packet import AuthPacket

# IANA assignment for EAP-TTLS.
EAP_TYPE_TTLS = 21

# RFC 5281 §11.1 — Diameter AVP Flags. V (0x80) is set when the
# Vendor-ID field is present; M (0x40) signals "Mandatory". RFC 5281
# §11.2 requires User-Name and User-Password AVPs to carry the M flag.
AVP_FLAG_VENDOR = 0x80
AVP_FLAG_MANDATORY = 0x40

# RADIUS attribute codes reused as Diameter AVP codes for TTLS PAP.
# User-Name and User-Password are RFC 2865 attribute 1 / 2.
AVP_USER_NAME = 1
AVP_USER_PASSWORD = 2


def encode_diameter_avp(
    code: int,
    data: bytes,
    flags: int = AVP_FLAG_MANDATORY,
    vendor_id: int | None = None,
) -> bytes:
    """Encode one Diameter AVP per RFC 6733 §4.1.

    The header is 8 bytes (12 with Vendor-ID), then the data field,
    then zero-padding to the next 4-byte boundary. The 24-bit
    ``Length`` covers the header + data but excludes the padding —
    that's the on-wire length receivers use to find the next AVP.
    """
    if vendor_id is not None:
        flags |= AVP_FLAG_VENDOR
        header_len = 12
    else:
        header_len = 8
    body_len = header_len + len(data)
    # Pack code(4) + flags(1) + length(3). Length is 24-bit big-endian,
    # which struct can't express directly — pack as 4-byte int and slice
    # off the high byte.
    code_bytes = struct.pack("!I", code)
    length_bytes = struct.pack("!I", body_len)[1:]
    out = code_bytes + bytes([flags]) + length_bytes
    if vendor_id is not None:
        out += struct.pack("!I", vendor_id)
    out += data
    # Pad to 4-byte alignment with NUL bytes.
    pad = (-body_len) % 4
    if pad:
        out += b"\x00" * pad
    return out


def decode_diameter_avps(buffer: bytes) -> list[tuple[int, int, int | None, bytes]]:
    """Decode a concatenated AVP stream into ``(code, flags, vendor, data)``.

    Skips the inter-AVP zero padding the encoder inserts. Raises
    ``ValueError`` if a header is truncated or claims a length that
    overruns the buffer — symptoms of either a corrupted record or a
    decoder/encoder mismatch a test should catch.
    """
    out: list[tuple[int, int, int | None, bytes]] = []
    cursor = 0
    while cursor < len(buffer):
        if len(buffer) - cursor < 8:
            raise ValueError(
                f"AVP header truncated at offset {cursor}: "
                f"need 8 bytes, got {len(buffer) - cursor}"
            )
        code = struct.unpack("!I", buffer[cursor : cursor + 4])[0]
        flags = buffer[cursor + 4]
        length = int.from_bytes(buffer[cursor + 5 : cursor + 8], "big")
        if length < 8 or cursor + length > len(buffer):
            raise ValueError(
                f"AVP at offset {cursor} claims length {length} which "
                f"overruns the {len(buffer) - cursor}-byte remaining buffer"
            )
        header_end = cursor + 8
        if flags & AVP_FLAG_VENDOR:
            if length < 12 or cursor + 12 > len(buffer):
                raise ValueError(
                    f"AVP at offset {cursor} sets V flag but length {length} "
                    "leaves no room for the Vendor-ID"
                )
            vendor: int | None = struct.unpack("!I", buffer[cursor + 8 : cursor + 12])[
                0
            ]
            header_end = cursor + 12
        else:
            vendor = None
        data = buffer[header_end : cursor + length]
        out.append((code, flags, vendor, data))
        # Advance past the AVP plus 4-byte alignment padding.
        cursor += length + ((-length) % 4)
    return out


class TtlsMethod(TlsEapMethodBase):
    """EAP-TTLS supplicant driver with PAP as the inner method.

    One instance per conversation. Inner credentials are populated
    from the outer packet's ``User-Name`` and ``User-Password`` on
    first respond — the same convention every other pyrad2 EAP method
    uses — so callers don't need to thread them through the
    constructor.

    Server-only cert authentication is the default; pass
    ``client_cert`` / ``client_key`` to opt in to mutual TLS. TTLS
    deployments rarely use it: the inner password method authenticates
    the user, and the outer cert authenticates the server.

    The TLS-EAP framing, fragmentation, and engine state machine all
    live in :class:`pyrad2.eap._tls_eap.TlsEapMethodBase`. TTLS just
    sets :attr:`EAP_TYPE = 21`, takes the anonymous-outer default, and
    overrides :meth:`_handle_inner` to push the PAP credentials once
    after the handshake completes.
    """

    EAP_TYPE = EAP_TYPE_TTLS
    DEFAULT_IDENTITY_FALLBACK = b"anonymous"

    def __init__(self, *args: object, **kwargs: object) -> None:
        # ``outer_identity`` keeps the same kwarg name PEAP uses —
        # tests and existing callers pass it through as a clearer
        # intent label than the base ABC's ``identity``. Map it
        # explicitly so the public signature stays back-compatible.
        outer_identity = kwargs.pop("outer_identity", None)
        if outer_identity is not None and "identity" not in kwargs:
            kwargs["identity"] = outer_identity
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        # Flip the moment we've pushed the inner AVPs into the TLS
        # plaintext queue — keeps the supplicant from re-sending them
        # on every subsequent round (the server's ACK rounds while it
        # processes our auth, for instance).
        self._inner_sent = False

    def _handle_inner(self, pkt: "AuthPacket", body: bytes) -> None:
        """Push inner PAP credentials once on first handshake-done round.

        Unlike PEAP, TTLS has no inbound inner exchange to drive — the
        supplicant just writes the AVPs into TLS plaintext as soon as
        the handshake completes. ``self._inner_sent`` guards against
        re-emitting the password on later ACK rounds while the server
        is still processing.
        """
        if self._engine.handshake_done and not self._inner_sent:
            self._engine.write_plaintext(self._build_pap_avps(pkt))
            self._inner_sent = True

    @staticmethod
    def _build_pap_avps(pkt: "AuthPacket") -> bytes:
        """Encode the User-Name + User-Password AVPs as one TLS payload.

        RFC 5281 §11.2 requires both AVPs to carry the M (Mandatory)
        flag and uses the RADIUS attribute codes directly. PAP doesn't
        obfuscate the password — that's by design; the TLS wrapper is
        the confidentiality boundary.
        """
        user_name = TtlsMethod._extract(pkt, 1, "User-Name")
        user_password = TtlsMethod._extract(pkt, 2, "User-Password")
        if user_name is None:
            raise ValueError(
                "EAP-TTLS PAP requires a User-Name attribute on the outer packet"
            )
        if user_password is None:
            raise ValueError(
                "EAP-TTLS PAP requires a User-Password attribute on the outer packet"
            )
        return encode_diameter_avp(AVP_USER_NAME, user_name) + encode_diameter_avp(
            AVP_USER_PASSWORD, user_password
        )

    @staticmethod
    def _extract(pkt: "AuthPacket", code: int, name: str) -> bytes | None:
        """Pull the first value of an attribute either by code or by name.

        The outer ``AuthPacket`` indexes attributes by integer code;
        the synthetic ``FakeAuthPacket`` used in tests does too but
        also accepts string keys. Try both.
        """
        for key in (code, name):
            try:
                if key in pkt:
                    raw = pkt[key][0]
                    return raw.encode("utf-8") if isinstance(raw, str) else raw
            except (TypeError, KeyError):
                continue
        return None
