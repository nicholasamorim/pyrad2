import binascii
import ssl
import struct
from asyncio import StreamReader
from collections.abc import Buffer
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network


def EncodeString(origstr: str) -> bytes:
    """Encode a string to bytes, ensuring it is UTF-8 encoded."""
    if len(origstr) > 253:
        raise ValueError("Can only encode strings of <= 253 characters")
    if isinstance(origstr, str):
        return origstr.encode("utf-8")
    else:
        return origstr


def EncodeOctets(octetstring: str) -> str | bytes:
    """Encode raw octet string (already in bytes)."""
    # Check for max length of the hex encoded with 0x prefix, as a sanity check
    if len(octetstring) > 508:
        raise ValueError("Can only encode strings of <= 253 characters")

    hexstring: str | bytes
    encoded_octets: str | bytes
    if isinstance(octetstring, bytes) and octetstring.startswith(b"0x"):
        hexstring = octetstring.split(b"0x")[1]
        encoded_octets = binascii.unhexlify(hexstring)
    elif isinstance(octetstring, str) and octetstring.startswith("0x"):
        hexstring = octetstring.split("0x")[1]
        encoded_octets = binascii.unhexlify(hexstring)
    elif isinstance(octetstring, str) and octetstring.isdecimal():
        encoded_octets = struct.pack(">L", int(octetstring)).lstrip(b"\x00")
    else:
        encoded_octets = octetstring

    # Check for the encoded value being longer than 253 chars
    if len(encoded_octets) > 253:
        raise ValueError("Can only encode strings of <= 253 characters")

    return encoded_octets


def EncodeAddress(addr: str) -> bytes:
    """Encode an IPv4 address (dotted string) to 4-byte format."""
    if not isinstance(addr, str):
        raise TypeError("Address has to be a string")
    return IPv4Address(addr).packed


def EncodeIPv6Prefix(addr: str) -> bytes:
    """Encode an IPv6 address and prefix length to 18-byte format."""
    if not isinstance(addr, str):
        raise TypeError("IPv6 Prefix has to be a string")
    ip = IPv6Network(addr, strict=False)
    return struct.pack("2B", *[0, ip.prefixlen]) + ip.network_address.packed


def EncodeIPv6Address(addr: str) -> bytes:
    """Encode an IPv6 address (as string) to 16-byte format."""
    if not isinstance(addr, str):
        raise TypeError("IPv6 Address has to be a string")
    return IPv6Address(addr).packed


def EncodeAscendBinary(orig_str: str) -> bytes:
    """Encode binary data in Ascend-specific format (length prefixed)."""
    """
    Format: List of type=value pairs separated by spaces.

    Example: 'family=ipv4 action=discard direction=in dst=10.10.255.254/32'

    Note: redirect(0x20) action is added for http-redirect (walled garden) use case

    Type:
        family      ipv4(default) or ipv6
        action      discard(default) or accept or redirect
        direction   in(default) or out
        src         source prefix (default ignore)
        dst         destination prefix (default ignore)
        proto       protocol number / next-header number (default ignore)
        sport       source port (default ignore)
        dport       destination port (default ignore)
        sportq      source port qualifier (default 0)
        dportq      destination port qualifier (default 0)

    Source/Destination Port Qualifier:
        0   no compare
        1   less than
        2   equal to
        3   greater than
        4   not equal to
    """

    terms = {
        "family": b"\x01",
        "action": b"\x00",
        "direction": b"\x01",
        "src": b"\x00\x00\x00\x00",
        "dst": b"\x00\x00\x00\x00",
        "srcl": b"\x00",
        "dstl": b"\x00",
        "proto": b"\x00",
        "sport": b"\x00\x00",
        "dport": b"\x00\x00",
        "sportq": b"\x00",
        "dportq": b"\x00",
    }

    family = "ipv4"
    ip: IPv4Network | IPv6Network

    for t in orig_str.split(" "):
        key, value = t.split("=")
        if key == "family" and value == "ipv6":
            family = "ipv6"
            terms[key] = b"\x03"
            if terms["src"] == b"\x00\x00\x00\x00":
                terms["src"] = 16 * b"\x00"
            if terms["dst"] == b"\x00\x00\x00\x00":
                terms["dst"] = 16 * b"\x00"
        elif key == "action" and value == "accept":
            terms[key] = b"\x01"
        elif key == "action" and value == "redirect":
            terms[key] = b"\x20"
        elif key == "direction" and value == "out":
            terms[key] = b"\x00"
        elif key == "src" or key == "dst":
            if family == "ipv4":
                ip = IPv4Network(value)
            else:
                ip = IPv6Network(value)
            terms[key] = ip.network_address.packed
            terms[key + "l"] = struct.pack("B", ip.prefixlen)
        elif key == "sport" or key == "dport":
            terms[key] = struct.pack("!H", int(value))
        elif key == "sportq" or key == "dportq" or key == "proto":
            terms[key] = struct.pack("B", int(value))

    trailer = 8 * b"\x00"

    result = b"".join(
        (
            terms["family"],
            terms["action"],
            terms["direction"],
            b"\x00",
            terms["src"],
            terms["dst"],
            terms["srcl"],
            terms["dstl"],
            terms["proto"],
            b"\x00",
            terms["sport"],
            terms["dport"],
            terms["sportq"],
            terms["dportq"],
            b"\x00\x00",
            trailer,
        )
    )
    return result


def EncodeInteger(num: int, format: str = "!I") -> bytes:
    """Encode a 32-bit unsigned integer to 4-byte big-endian."""
    try:
        num = int(num)
    except (ValueError, TypeError):
        raise TypeError("Can not encode non-integer as integer")
    return struct.pack(format, num)


def EncodeInteger64(num: int, format: str = "!Q") -> bytes:
    """Encode a 64-bit unsigned integer to 8-byte big-endian."""
    try:
        num = int(num)
    except (ValueError, TypeError):
        raise TypeError("Can not encode non-integer as integer64")
    return struct.pack(format, num)


def EncodeDate(num: int) -> bytes:
    """Encode a UNIX timestamp (int) to 4-byte format."""
    if not isinstance(num, int):
        raise TypeError("Can not encode non-integer as date")
    return struct.pack("!I", num)


def DecodeString(orig_str: bytes) -> str:
    """Decode UTF-8 bytes into a string."""
    try:
        return orig_str.decode("utf-8")
    except UnicodeDecodeError:
        # Non-UTF-8 data displayed in hexadecimal form
        return orig_str.hex()


def DecodeOctets(orig_bytes: bytes) -> bytes:
    """Return bytes unchanged (octet format)."""
    return orig_bytes


def DecodeAddress(addr: Buffer) -> str:
    """Decode 4-byte data into an IPv4 dotted string."""
    return ".".join(map(str, struct.unpack("BBBB", addr)))


def DecodeIPv6Prefix(addr: bytes | bytearray) -> str:
    """Decode 18-byte IPv6 prefix format into address/prefix tuple."""
    addr = addr + b"\x00" * (18 - len(addr))
    _, length, prefix = ":".join(
        map("{:x}".format, struct.unpack("!BB" + "H" * 8, addr))
    ).split(":", 2)
    return str(IPv6Network("{}/{}".format(prefix, int(length, 16))))


def DecodeIPv6Address(addr: bytes | bytearray) -> str:
    """Decode 16-byte IPv6 address into a readable string."""
    addr = addr + b"\x00" * (16 - len(addr))
    prefix = ":".join(map("{:x}".format, struct.unpack("!" + "H" * 8, addr)))
    return str(IPv6Address(prefix))


def DecodeAscendBinary(orig_bytes: bytes) -> bytes:
    """Decode Ascend-specific binary format (length-prefixed)."""
    return orig_bytes


def DecodeInteger(num: Buffer, format: str = "!I") -> bytes:
    """Decode 4-byte big-endian unsigned integer."""
    return (struct.unpack(format, num))[0]


def DecodeInteger64(num: Buffer, format: str = "!Q") -> bytes:
    """Decode 8-byte big-endian unsigned integer."""
    return (struct.unpack(format, num))[0]


def DecodeDate(num: Buffer) -> bytes:
    """Decode 4-byte UNIX timestamp into an integer."""
    return (struct.unpack("!I", num))[0]


def EncodeAttr(datatype: str, value) -> bytes | str:
    """Encode a RADIUS attribute (type, value, length) into bytes."""
    if datatype == "string":
        return EncodeString(value)
    elif datatype == "octets":
        return EncodeOctets(value)
    elif datatype == "integer":
        return EncodeInteger(value)
    elif datatype == "ipaddr":
        return EncodeAddress(value)
    elif datatype == "ipv6prefix":
        return EncodeIPv6Prefix(value)
    elif datatype == "ipv6addr":
        return EncodeIPv6Address(value)
    elif datatype == "abinary":
        return EncodeAscendBinary(value)
    elif datatype == "signed":
        return EncodeInteger(value, "!i")
    elif datatype == "short":
        return EncodeInteger(value, "!H")
    elif datatype == "byte":
        return EncodeInteger(value, "!B")
    elif datatype == "date":
        return EncodeDate(value)
    elif datatype == "integer64":
        return EncodeInteger64(value)
    else:
        raise ValueError("Unknown attribute type %s" % datatype)


def DecodeAttr(datatype: str, value) -> bytes | str:
    """Decode a RADIUS attribute from bytes into a type and value."""
    if datatype == "string":
        return DecodeString(value)
    elif datatype == "octets":
        return DecodeOctets(value)
    elif datatype == "integer":
        return DecodeInteger(value)
    elif datatype == "ipaddr":
        return DecodeAddress(value)
    elif datatype == "ipv6prefix":
        return DecodeIPv6Prefix(value)
    elif datatype == "ipv6addr":
        return DecodeIPv6Address(value)
    elif datatype == "abinary":
        return DecodeAscendBinary(value)
    elif datatype == "signed":
        return DecodeInteger(value, "!i")
    elif datatype == "short":
        return DecodeInteger(value, "!H")
    elif datatype == "byte":
        return DecodeInteger(value, "!B")
    elif datatype == "date":
        return DecodeDate(value)
    elif datatype == "integer64":
        return DecodeInteger64(value)
    else:
        raise ValueError("Unknown attribute type %s" % datatype)


def get_cert_fingerprint(cert: bytes) -> str:
    """Generate SHA-256 fingerprint from a certificate."""
    der_bytes = ssl.PEM_cert_to_DER_cert(ssl.DER_cert_to_PEM_cert(cert))
    hash = sha256(der_bytes).digest()
    # Return in base64 or hex
    return hash.hex()  # or base64.b64encode(sha256).decode()


def get_client_fingerprint(ssl_object: ssl.SSLSocket) -> str | None:
    """Returns SHA-256 fingerprint of the client certificate."""
    cert = ssl_object.getpeercert(binary_form=True)
    if cert:
        fingerprint = sha256(cert).hexdigest()
        return fingerprint
    return None


async def read_radius_packet(reader: StreamReader) -> bytes:
    """Read a full RADIUS packet from the stream.

    There's no built-in framing in RadSec, so we can't read a fixed-size packet.
    Instead, we read the header first to determine the length of the packet,
    and then read the rest of the packet based on that length.

    RADIUS packets are prefixed with a 4-byte header:
        - Code (1 byte)
        - Identifier (1 byte)
        - Length (2 bytes)

    The length includes the header, so the minimum length is 20 bytes
    (4-byte header + 16-byte Authenticator).
    If the length is less than 20, it is considered invalid.

    :param reader: asyncio StreamReader to read from
    :return: Full RADIUS packet as bytes
    """
    header = await reader.readexactly(4)
    code, identifier, length = struct.unpack("!BBH", header)

    if length < 20:
        raise ValueError("Invalid RADIUS packet length")

    body = await reader.readexactly(length - 4)
    return header + body
