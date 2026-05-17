"""RADIUS protocol constants shared across the package.

Values mirror those defined in the relevant RFCs (RFC 2865, RFC 3576,
RFC 3748, RFC 5176, RFC 5997).
"""

from enum import IntEnum


class PacketType(IntEnum):
    """RADIUS packet codes as defined by the IANA registry.

    Used as the ``code`` attribute on every packet — both incoming
    requests dispatched by the server and outgoing replies built with
    ``create_reply_packet``.
    """

    AccessRequest = 1
    AccessAccept = 2
    AccessReject = 3
    AccountingRequest = 4
    AccountingResponse = 5
    AccessChallenge = 11
    StatusServer = 12
    StatusClient = 13
    DisconnectRequest = 40
    DisconnectACK = 41
    DisconnectNAK = 42
    CoARequest = 43
    CoAACK = 44
    CoANAK = 45


class ErrorCause(IntEnum):
    """RFC 5176 Error-Cause attribute values used in CoA/Disconnect NAKs."""

    UnsupportedExtension = 406


class EAPPacketType(IntEnum):
    """EAP packet code field (RFC 3748 §4)."""

    REQUEST = 1
    RESPONSE = 2


class EAPType(IntEnum):
    """EAP method type field (RFC 3748 §5)."""

    IDENTITY = 1


DATATYPES = frozenset(
    [
        "string",
        "ipaddr",
        "integer",
        "date",
        "octets",
        "abinary",
        "ipv6addr",
        "ipv6prefix",
        "short",
        "byte",
        "signed",
        "ifid",
        "ether",
        "tlv",
        "integer64",
    ]
)
