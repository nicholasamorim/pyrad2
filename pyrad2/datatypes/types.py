import binascii

# import enum
import struct
from abc import ABC, abstractmethod
from datetime import datetime
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)
from typing import Any

from netaddr import EUI, core

from .base import AbstractDataType


class AbstractType(AbstractDataType, ABC):
    """
    Abstract class for data types
    """

    @abstractmethod
    def decode(self, raw: bytes, *args, **kwargs) -> Any:
        """Decode python data structure from bytestring

        Args:
            raw (bytes): Raw attribute value
        """

    def get_value(self, attribute, packet: bytes, offset: int) -> tuple[Any, int]:
        _, attr_len = struct.unpack("!BB", packet[offset : offset + 2])[0:2]
        return packet[offset + 2 : offset + attr_len], attr_len


class AscendBinary(AbstractType):
    def __init__(self):
        super().__init__("abinary")

    def encode(self, attribute, decoded, *args, **kwargs):
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
        for t in decoded.split(" "):
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
            elif key in ("src", "dst"):
                if family == "ipv4":
                    ip = IPv4Network(value)
                else:
                    ip = IPv6Network(value)
                terms[key] = ip.network_address.packed
                terms[key + "l"] = struct.pack("B", ip.prefixlen)
            elif key in ("sport", "dport"):
                terms[key] = struct.pack("!H", int(value))
            elif key in ("sportq", "dportq", "proto"):
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

    def decode(self, raw, *args, **kwargs):
        #  just return the raw binary string
        return raw

    def print(self, attribute, decoded, *args, **kwargs):
        #  the binary string is what we are looking for
        return decoded

    def parse(self, dictionary, string, *args, **kwargs):
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        # abinary strings are stored as strings, so parse and return as is
        return string


class Byte(AbstractType):
    def __init__(self):
        super().__init__("byte")

    def encode(self, attribute, decoded, *args, **kwargs):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError("Can not encode non-integer as byte") from exc
        return struct.pack("!B", num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack("!B", raw)[0]

    def print(self, attribute, decoded, *args, **kwargs):
        #  cast int to string before returning
        return str(decoded)

    def parse(self, dictionary, string, *args, **kwargs):
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError("Can not parse non-integer as byte") from e
        else:
            if num < 0:
                raise ValueError("Parsed value too small for byte")
            if num > 255:
                raise ValueError("Parsed value too large for byte")
            return num


class Date(AbstractType):
    def __init__(self):
        super().__init__("date")

    def encode(self, attribute, decoded: int, *args, **kwargs) -> bytes:
        if not isinstance(decoded, int):
            raise TypeError("Can not encode non-integer as date")
        return struct.pack("!I", decoded)

    def decode(self, raw: bytes, *args, **kwargs) -> int:
        #  dates are stored as ints
        return (struct.unpack("!I", raw))[0]

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        #  turn seconds since epoch into timestamp with given format
        return datetime.fromtimestamp(decoded).strftime("%Y-%m-%dT%H:%M:%S")

    def parse(self, dictionary, string: str, *args, **kwargs) -> int:
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        try:
            #  parse string using given string, and return seconds since epoch
            #  as an int
            return int(datetime.strptime(string, "%Y-%m-%dT%H:%M:%S").timestamp())
        except ValueError as e:
            raise TypeError("Failed to parse date") from e


class Ether(AbstractType, ABC):
    """Datatype class for ethernet addresses"""

    def __init__(self):
        super().__init__("ether")

    def encode(self, attribute, decoded, *args, **kwargs) -> bytes:
        return struct.pack("!6B", *map(lambda x: int(x, 16), decoded.split(":")))

    def decode(self, raw, *args, **kwargs) -> EUI:
        #  return EUI object containing mac address
        return EUI(":".join(map("{0:02x}".format, struct.unpack("!6B", raw))))

    def print(self, attribute, decoded, *args, **kwargs) -> EUI:
        return decoded

    def parse(self, dictionary, string: str, *args, **kwargs) -> EUI:
        if not isinstance(string, str):
            raise TypeError("Can not encode non-string as ethernet address")

        try:
            return EUI(string)
        except core.AddrFormatError as e:
            raise ValueError("Could not decode ethernet address") from e


class Ifid(AbstractType, ABC):
    """Datatype class for IFID (IPV6 interface ID)"""

    def __init__(self):
        super().__init__("ifid")

    def encode(self, attribute, decoded, *args, **kwargs) -> bytes:
        return struct.pack("!HHHH", *map(lambda x: int(x, 16), decoded.split(":")))

    def decode(self, raw, *args, **kwargs) -> str:
        return ":".join(map("{0:04x}".format, struct.unpack("!HHHH", raw)))

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        # Following freeradius, IFIDs are displayed as a hex without any
        # delimiters
        return decoded.replace(":", "")

    def parse(self, dictionary, string, *args, **kwargs) -> str:
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        #  adds a : delimiter after every second character
        return ":".join((string[i : i + 2] for i in range(0, len(string), 2)))


class Integer(AbstractType):
    """
    leaf datatype class for integers
    """

    def __init__(self):
        super().__init__("integer")

    def encode(
        self, attribute, decoded: str | bytes | bytearray, *args, **kwargs
    ) -> bytes:
        msg = f"Can not encode non-integer as integer: {decoded}"  # type: ignore

        try:
            num = int(decoded)
        except (TypeError, ValueError):
            try:
                # Value may be hexadecimal
                num = int(decoded, 0)
            except (TypeError, ValueError) as exc:
                raise TypeError(msg) from exc
        except Exception as exc:
            raise TypeError(msg) from exc

        return struct.pack("!I", num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack("!I", raw)[0]

    def print(self, attribute, decoded, *args, **kwargs):
        return str(decoded)

    def parse(self, dictionary, string, *args, **kwargs):
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError("Can not parse non-integer as int") from e
        else:
            if num < 0:
                raise ValueError("Parsed value too small for int")
            if num > 4294967295:
                raise ValueError("Parsed value too large for int")
            return num


class Integer64(AbstractType):
    """
    leaf datatype class for 64bit integers
    """

    def __init__(self):
        super().__init__("integer64")

    def encode(self, attribute, decoded, *args, **kwargs) -> bytes:
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError("Can not encode non-integer as 64bit integer") from exc
        return struct.pack("!Q", num)

    def decode(self, raw, *args, **kwargs) -> int:
        return struct.unpack("!Q", raw)[0]

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        return str(decoded)

    def parse(self, dictionary, string, *args, **kwargs) -> int:
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError("Can not parse non-integer as int64") from e
        else:
            if num < 0:
                raise ValueError("Parsed value too small for int64")
            if num > 18446744073709551615:
                raise ValueError("Parsed value too large for int64")
            return num


class Ipaddr(AbstractType):
    """
    leaf datatype class for ipv4 addresses
    """

    def __init__(self):
        super().__init__("ipaddr")

    def encode(self, attribute, decoded: str, *args, **kwargs) -> bytes:
        if not isinstance(decoded, str):
            raise TypeError("Address has to be a string")
        return IPv4Address(decoded).packed

    def decode(self, raw, *args, **kwargs) -> str:
        #  stored as strings, not ipaddress objects
        return ".".join(map(str, struct.unpack("BBBB", raw)))

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        #  since object is already stored as a string, just return it as is
        return decoded

    def parse(self, dictionary, string, *args, **kwargs) -> str:
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        try:
            #  check if string is valid ipv4 address, but still returning the
            #  string representation
            return IPv4Address(string).exploded
        except AddressValueError as e:
            raise TypeError("Parsing invalid IPv4 address") from e


class Ipv6addr(AbstractType):
    """
    leaf datatype class for ipv6 addresses
    """

    def __init__(self):
        super().__init__("ipv6addr")

    def encode(self, attribute, decoded: str, *args, **kwargs) -> bytes:
        if not isinstance(decoded, str):
            raise TypeError("IPv6 Address has to be a string")
        return IPv6Address(decoded).packed

    def decode(self, raw, *args, **kwargs) -> str:
        addr = raw + b"\x00" * (16 - len(raw))
        prefix = ":".join(map(lambda x: f"{0:x}", struct.unpack("!" + "H" * 8, addr)))
        return str(IPv6Address(prefix))

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        if not isinstance(decoded, str):
            raise TypeError(f"Parsing expects a string, got {type(decoded)}")

        try:
            #  check if valid address, but return string representation
            return IPv6Address(decoded).exploded
        except AddressValueError as e:
            raise TypeError("Parsing invalid IPv6 address") from e

    def parse(self, dictionary, string: str, *args, **kwargs) -> str:
        return string


class Ipv6prefix(AbstractType):
    """
    leaf datatype class for ipv6 prefixes
    """

    def __init__(self):
        super().__init__("ipv6prefix")

    def encode(self, attribute, decoded: str, *args, **kwargs) -> bytes:
        if not isinstance(decoded, str):
            raise TypeError("IPv6 Prefix has to be a string")
        ip = IPv6Network(decoded)
        return struct.pack("2B", *[0, ip.prefixlen]) + ip.network_address.packed

    def decode(self, raw, *args, **kwargs) -> str:
        addr = raw + b"\x00" * (18 - len(raw))
        _, length, prefix = ":".join(
            map(lambda x: f"{0:x}", struct.unpack("!BB" + "H" * 8, addr))
        ).split(":", 2)
        #  returns string representation in the form of <Prefix>/<prefix len>
        return str(IPv6Network(f"{prefix}/{int(length, 16)}"))

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        #  we already store this value as a string, so just return it as is
        return decoded

    def parse(self, dictionary, string, *args, **kwargs) -> str:
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        try:
            return str(IPv6Network(string))
        except AddressValueError as e:
            raise TypeError("Parsing invalid IPv6 prefix") from e


class Octets(AbstractType):
    """
    leaf datatype class for octets
    """

    def __init__(self):
        super().__init__("octets")

    def encode(self, attribute, decoded: bytes, *args, **kwargs) -> bytes:
        # Check for max length of the hex encoded with 0x prefix, as a sanity check
        if len(decoded) > 508:
            raise ValueError("Can only encode strings of <= 253 characters")

        if isinstance(decoded, bytes) and decoded.startswith(b"0x"):
            hexstring = decoded.split(b"0x")[1]
            encoded_octets = binascii.unhexlify(hexstring)
        elif isinstance(decoded, str) and decoded.startswith("0x"):
            hexstring = decoded.split("0x")[1]
            encoded_octets = binascii.unhexlify(hexstring)
        elif isinstance(decoded, str) and decoded.isdecimal():
            encoded_octets = struct.pack(">L", int(decoded)).lstrip(b"\x00")
        else:
            encoded_octets = decoded

        # Check for the encoded value being longer than 253 chars
        if len(encoded_octets) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")

        return encoded_octets

    def decode(self, raw, *args, **kwargs):
        return raw

    def print(self, attribute, decoded, *args, **kwargs):
        return decoded

    def parse(self, dictionary, string, *args, **kwargs):
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        return string


class Short(AbstractType):
    """Datatype class for short integers"""

    def __init__(self):
        super().__init__("short")

    def encode(self, attribute, decoded, *args, **kwargs) -> bytes:
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError("Can not encode non-integer as integer") from exc
        return struct.pack("!H", num)

    def decode(self, raw, *args, **kwargs) -> str:
        return struct.unpack("!H", raw)[0]

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        return str(decoded)

    def parse(self, dictionary, string: str, *args, **kwargs) -> int:
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError("Can not parse non-integer as short") from e
        else:
            if num < 0:
                raise ValueError("Parsed value too small for short")
            if num > 65535:
                raise ValueError("Parsed value too large for short")
            return num


class Signed(AbstractType):
    """Data type class for signed integers"""

    def __init__(self):
        super().__init__("signed")

    def encode(self, attribute, decoded, *args, **kwargs) -> bytes:
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError("Can not encode non-integer as signed integer") from exc
        return struct.pack("!i", num)

    def decode(self, raw, *args, **kwargs) -> str:
        return struct.unpack("!i", raw)[0]

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        return str(decoded)

    def parse(self, dictionary, string, *args, **kwargs) -> int:
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError("Can not parse non-integer as signed") from e
        else:
            if num < -2147483648:
                raise ValueError("Parsed value too small for signed")
            if num > 2147483647:
                raise ValueError("Parsed value too large for signed")
            return num


class String(AbstractType):
    """
    leaf datatype class for strings
    """

    def __init__(self):
        super().__init__("string")

    def encode(self, attribute, decoded: str, *args, **kwargs) -> bytes:
        if len(decoded) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")
        if isinstance(decoded, str):
            return decoded.encode("utf-8")
        return decoded

    def decode(self, raw, *args, **kwargs) -> str:
        return raw.decode("utf-8")

    def print(self, attribute, decoded, *args, **kwargs) -> str:
        return decoded

    def parse(self, dictionary, string, *args, **kwargs) -> str:
        if not isinstance(string, str):
            raise TypeError(f"Parsing expects a string, got {type(string)}")

        return string
