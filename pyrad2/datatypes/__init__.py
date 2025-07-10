from . import types
from . import structural

RADIUS_TYPES = {
    "abinary": types.AscendBinary(),
    "byte": types.Byte(),
    "date": types.Date(),
    "ether": types.Ether(),
    "ifid": types.Ifid(),
    "integer": types.Integer(),
    "integer64": types.Integer64(),
    "ipaddr": types.Ipaddr(),
    "ipv6addr": types.Ipv6addr(),
    "ipv6prefix": types.Ipv6prefix(),
    "octets": types.Octets(),
    "short": types.Short(),
    "signed": types.Signed(),
    "string": types.String(),
    # Structural attributes
    "tlv": structural.TLV(),
    "vsa": structural.VSA(),
}
