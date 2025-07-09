"""
RADIUS uses dictionaries to define the attributes that can
be used in packets. The Dictionary class stores the attribute
definitions from one or more dictionary files.

Dictionary files are textfiles with one command per line.
Comments are specified by starting with a # character, and empty
lines are ignored.

The commands supported are::

```
ATTRIBUTE <attribute> <code> <type> [<vendor>]
specify an attribute and its type

VALUE <attribute> <valuename> <value>
specify a value attribute

VENDOR <name> <id>
specify a vendor ID

BEGIN-VENDOR <vendorname>
begin definition of vendor attributes

END-VENDOR <vendorname>
end definition of vendor attributes
```


The datatypes currently supported are:

```
+---------------+----------------------------------------------+
| type          | description                                  |
+===============+==============================================+
| string        | ASCII string                                 |
+---------------+----------------------------------------------+
| ipaddr        | IPv4 address                                 |
+---------------+----------------------------------------------+
| date          | 32 bits UNIX                                 |
+---------------+----------------------------------------------+
| octets        | arbitrary binary data                        |
+---------------+----------------------------------------------+
| abinary       | ascend binary data                           |
+---------------+----------------------------------------------+
| ipv6addr      | 16 octets in network byte order              |
+---------------+----------------------------------------------+
| ipv6prefix    | 18 octets in network byte order              |
+---------------+----------------------------------------------+
| integer       | 32 bits unsigned number                      |
+---------------+----------------------------------------------+
| signed        | 32 bits signed number                        |
+---------------+----------------------------------------------+
| short         | 16 bits unsigned number                      |
+---------------+----------------------------------------------+
| byte          | 8 bits unsigned number                       |
+---------------+----------------------------------------------+
| tlv           | Nested tag-length-value                      |
+---------------+----------------------------------------------+
| integer64     | 64 bits unsigned number                      |
+---------------+----------------------------------------------+
```

These datatypes are parsed but not supported:

```
+---------------+----------------------------------------------+
| type          | description                                  |
+===============+==============================================+
| ifid          | 8 octets in network byte order               |
+---------------+----------------------------------------------+
| ether         | 6 octets of hh:hh:hh:hh:hh:hh                |
|               | where 'h' is hex digits, upper or lowercase. |
+---------------+----------------------------------------------+
```
"""

from copy import copy
from typing import Any, Dict, Hashable, Optional

from pyrad2 import bidict, dictfile, tools
from pyrad2.constants import DATATYPES
from pyrad2.exceptions import ParseError

RadiusAttributeValue = int | str | bytes


class Attribute:
    """Represents a RADIUS attribute.

    Attributes:
        name (str): Attribute name
        code (int): RADIUS code
        type (str): Data type (e.g., 'string', 'ipaddr')
        vendor (int): Vendor ID (0 if standard)
        has_tag (bool): Whether attribute supports tags
        encrypt (int): Encryption type (0 = none)
        values (bidict.BiDict): Mapping of named values to their codes
    """

    def __init__(
        self,
        name: str,
        code: int,
        datatype: str,
        is_sub_attribute: bool = False,
        vendor: str = "",
        values=None,
        encrypt: int = 0,
        has_tag: bool = False,
    ):
        if datatype not in DATATYPES:
            raise ValueError("Invalid data type")
        self.name = name
        self.code = code
        self.type = datatype
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = has_tag
        self.values = bidict.BiDict()
        self.sub_attributes: dict = {}
        self.parent = None
        self.is_sub_attribute = is_sub_attribute
        if values:
            for key, value in values.items():
                self.values.Add(key, value)


class Dictionary:
    """RADIUS dictionary class.

    This class stores all information about vendors, attributes and their
    values as defined in RADIUS dictionary files.

    Attributes:
        vendors (bidict.BiDict): bidict mapping vendor name to vendor code
        attrindex (bidict.BiDict): bidict mapping
        attributes (bidict.BiDict): bidict mapping attribute name to attribute class
    """

    def __init__(self, dict: Optional[str] = None, *dicts):
        """Initialize a new Dictionary instance and load specified dictionary files.

        Args:
            dict (str): Path of dictionary file or file-like object to read
            dicts (list): Sequence of strings or files
        """
        self.vendors = bidict.BiDict()
        self.vendors.Add("", 0)
        self.attrindex = bidict.BiDict()
        self.attributes: Dict[Hashable, Any] = {}
        self.defer_parse: list[tuple[Dict, list]] = []

        if dict:
            self.ReadDictionary(dict)

        for i in dicts:
            self.ReadDictionary(i)

    def __len__(self) -> int:
        """Return the number of attributes defined."""
        return len(self.attributes)

    def __getitem__(self, key: Hashable):
        """Retrieve an Attribute by name."""
        return self.attributes[key]

    def __contains__(self, key: Hashable) -> bool:
        """Check if an attribute is defined in the dictionary."""
        return key in self.attributes

    has_key = __contains__

    def __ParseAttribute(self, state: dict, tokens: list):
        """Parse an ATTRIBUTE line from a dictionary file."""
        if len(tokens) not in [4, 5]:
            raise ParseError(
                "Incorrect number of tokens for attribute definition",
                name=state["file"],
                line=state["line"],
            )

        vendor = state["vendor"]
        has_tag = False
        encrypt = 0
        if len(tokens) >= 5:

            def keyval(o):
                kv = o.split("=")
                if len(kv) == 2:
                    return (kv[0], kv[1])
                else:
                    return (kv[0], None)

            options = [keyval(o) for o in tokens[4].split(",")]
            for key, val in options:
                if key == "has_tag":
                    has_tag = True
                elif key == "encrypt":
                    if val not in ["1", "2", "3"]:
                        raise ParseError(
                            "Illegal attribute encryption: %s" % val,
                            file=state["file"],
                            line=state["line"],
                        )
                    encrypt = int(val)

            if (not has_tag) and encrypt == 0:
                vendor = tokens[4]
                if not self.vendors.HasForward(vendor):
                    if vendor == "concat":
                        # ignore attributes with concat (freeradius compat.)
                        return None
                    else:
                        raise ParseError(
                            "Unknown vendor " + vendor,
                            file=state["file"],
                            line=state["line"],
                        )

        (attribute, code, datatype) = tokens[1:4]

        codes = code.split(".")

        # Codes can be sent as hex, or octal or decimal string representations.
        tmp = []
        for c in codes:
            if c.startswith("0x"):
                tmp.append(int(c, 16))
            elif c.startswith("0o"):
                tmp.append(int(c, 8))
            else:
                tmp.append(int(c, 10))
        codes = tmp

        is_sub_attribute = len(codes) > 1
        if len(codes) == 2:
            code = int(codes[1])
            parent_code = int(codes[0])
        elif len(codes) == 1:
            code = int(codes[0])
            parent_code = None
        else:
            raise ParseError("nested tlvs are not supported")

        datatype = datatype.split("[")[0]

        if datatype not in DATATYPES:
            raise ParseError(
                "Illegal type: " + datatype, file=state["file"], line=state["line"]
            )
        if vendor:
            if is_sub_attribute:
                key = (self.vendors.GetForward(vendor), parent_code, code)
            else:
                key = (self.vendors.GetForward(vendor), code)
        else:
            if is_sub_attribute:
                key = (parent_code, code)
            else:
                key = code

        self.attrindex.Add(attribute, key)
        self.attributes[attribute] = Attribute(
            attribute,
            code,
            datatype,
            is_sub_attribute,
            vendor,
            encrypt=encrypt,
            has_tag=has_tag,
        )
        if datatype == "tlv":
            # save attribute in tlvs
            state["tlvs"][code] = self.attributes[attribute]
        if is_sub_attribute:
            # save sub attribute in parent tlv and update their parent field
            state["tlvs"][parent_code].sub_attributes[code] = attribute
            self.attributes[attribute].parent = state["tlvs"][parent_code]

    def __ParseValue(self, state: dict, tokens: list, defer: bool) -> None:
        """Parse a VALUE line from a dictionary file."""
        if len(tokens) != 4:
            raise ParseError(
                "Incorrect number of tokens for value definition",
                file=state["file"],
                line=state["line"],
            )

        (attr, key, value) = tokens[1:]

        try:
            adef = self.attributes[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            raise ParseError(
                "Value defined for unknown attribute " + attr,
                file=state["file"],
                line=state["line"],
            )

        if adef.type in ["integer", "signed", "short", "byte", "integer64"]:
            value = int(value, 0)
        value = tools.EncodeAttr(adef.type, value)
        self.attributes[attr].values.Add(key, value)

    def __ParseVendor(self, state: dict, tokens: list) -> None:
        """Parse a VENDOR line, registering a new vendor."""
        if len(tokens) not in [3, 4]:
            raise ParseError(
                "Incorrect number of tokens for vendor definition",
                file=state["file"],
                line=state["line"],
            )

        # Parse format specification, but do
        # nothing about it for now
        if len(tokens) == 4:
            fmt = tokens[3].split("=")
            if fmt[0] != "format":
                raise ParseError(
                    "Unknown option '%s' for vendor definition" % (fmt[0]),
                    file=state["file"],
                    line=state["line"],
                )
            try:
                (_type, length) = tuple(int(a) for a in fmt[1].split(","))
                if _type not in [1, 2, 4] or length not in [0, 1, 2]:
                    raise ParseError(
                        "Unknown vendor format specification %s" % (fmt[1]),
                        file=state["file"],
                        line=state["line"],
                    )
            except ValueError:
                raise ParseError(
                    "Syntax error in vendor specification",
                    file=state["file"],
                    line=state["line"],
                )

        (vendorname, vendor) = tokens[1:3]
        self.vendors.Add(vendorname, int(vendor, 0))

    def __ParseBeginVendor(self, state: dict, tokens: list) -> None:
        """Start a block of attributes for a specific vendor."""
        if len(tokens) != 2:
            raise ParseError(
                "Incorrect number of tokens for begin-vendor statement",
                file=state["file"],
                line=state["line"],
            )

        vendor = tokens[1]

        if not self.vendors.HasForward(vendor):
            raise ParseError(
                "Unknown vendor %s in begin-vendor statement" % vendor,
                file=state["file"],
                line=state["line"],
            )

        state["vendor"] = vendor

    def __ParseEndVendor(self, state: dict, tokens: list):
        """End a block of vendor-specific attributes."""
        if len(tokens) != 2:
            raise ParseError(
                "Incorrect number of tokens for end-vendor statement",
                file=state["file"],
                line=state["line"],
            )

        vendor = tokens[1]

        if state["vendor"] != vendor:
            raise ParseError(
                "Ending non-open vendor" + vendor,
                file=state["file"],
                line=state["line"],
            )
        state["vendor"] = ""

    def ReadDictionary(self, file: str) -> None:
        """Parse a dictionary file.
        Reads a RADIUS dictionary file and merges its contents into the
        class instance.

        Args:
            file (str | io): Name of dictionary file to parse or a file-like object
        """

        fil = dictfile.DictFile(file)

        state: Dict[str, Any] = {}
        state["vendor"] = ""
        state["tlvs"] = {}
        self.defer_parse = []
        for line in fil:
            state["file"] = fil.File()
            state["line"] = fil.Line()
            line = line.split("#", 1)[0].strip()

            tokens = line.split()
            if not tokens:
                continue

            key = tokens[0].upper()
            if key == "ATTRIBUTE":
                self.__ParseAttribute(state, tokens)
            elif key == "VALUE":
                self.__ParseValue(state, tokens, True)
            elif key == "VENDOR":
                self.__ParseVendor(state, tokens)
            elif key == "BEGIN-VENDOR":
                self.__ParseBeginVendor(state, tokens)
            elif key == "END-VENDOR":
                self.__ParseEndVendor(state, tokens)

        for state, tokens in self.defer_parse:
            key = tokens[0].upper()
            if key == "VALUE":
                self.__ParseValue(state, tokens, False)
        self.defer_parse = []
