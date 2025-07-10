import ssl
import struct
from asyncio import StreamReader
from hashlib import sha256


def get_cert_fingerprint(cert: bytes) -> str:
    """Generate SHA-256 fingerprint from a certificate."""
    der_bytes = ssl.PEM_cert_to_DER_cert(ssl.DER_cert_to_PEM_cert(cert))
    hash = sha256(der_bytes).digest()
    # Return in base64 or hex
    return hash.hex()  # or base64.b64encode(sha256).decode()


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


def tlv_name_to_codes(dictionary, tlv):
    """Recursive function to change all the keys in a TLV from strings to
    codes.

    Args:
        dictionary (Dictionary): dictionary containing attribute name to key mappings
        tlv (str): TLV with attribute names

    Returns:
        tlv: TLV with attribute keys
    """
    updated = {}
    for key, value in tlv.items():
        code = dictionary.attrindex[key]

        #  in nested structures, pyrad stored the entire OID in a single tuple
        #  but we only want the last code
        if isinstance(code, tuple):
            code = code[-1]

        if isinstance(value, str):
            updated[code] = value
        else:
            updated[code] = tlv_name_to_codes(dictionary, value)
    return updated


def vsa_name_to_codes(dictionary, vsa):
    """ """
    updated = {"Vendor-Specific": {}}

    for vendor, tlv in vsa["Vendor-Specific"].items():
        vendor_id = dictionary.vendors[vendor]
        vendor_tlv = tlv_name_to_codes(dictionary, tlv)
        updated["Vendor-Specific"][vendor_id] = vendor_tlv

    return updated
