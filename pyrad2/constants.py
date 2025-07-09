# Packet codes
from enum import IntEnum


class PacketType(IntEnum):
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


class EAPPacketType(IntEnum):
    REQUEST = 1
    RESPONSE = 2


class EAPType(IntEnum):
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
