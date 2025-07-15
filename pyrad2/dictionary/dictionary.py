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

from pyrad2 import dictfile
from pyrad2.bidict import BiDict
from pyrad2.dictionary.vendor import Vendor
from pyrad2.dictionary.attribute import AttributeStack
from pyrad2.datatypes import RADIUS_TYPES
from pyrad2.exceptions import ParseError

from .attribute import Attribute

RadiusAttributeValue = int | str | bytes


class Dictionary:
    """RADIUS dictionary class.

    This class stores all information about vendors, attributes and their
    values as defined in RADIUS dictionary files.

    Attributes:
        vendors (BiDict): bidict mapping vendor name to vendor code
        attrindex (BiDict): bidict mapping
        attributes (BiDict): bidict mapping attribute name to attribute class
    """

    def __init__(self, dict: Optional[str] = None, *dicts):
        """Initialize a new Dictionary instance and load specified dictionary files.

        Args:
            dict (str): Path of dictionary file or file-like object to read
            dicts (list): Sequence of strings or files
        """
        self.vendors = BiDict()
        self.vendors.Add("", 0)
        self.attrindex = BiDict()
        self.attributes: Dict[Hashable, Any] = {}
        self.defer_parse: list[tuple[Dict, list]] = []

        self.stack = AttributeStack()
        # the global attribute namespace is the first layer
        self.stack.push(self.attributes, self.attrindex)  # type: ignore

        if dict:
            self.ReadDictionary(dict)

        for i in dicts:
            self.ReadDictionary(i)

    def __len__(self) -> int:
        """Return the number of attributes defined."""
        return len(self.attributes)

    def __getitem__(self, key: Hashable):
        """Retrieve an Attribute by name."""
        # allow indexing attributes by number (instead of name).
        # since the key must be an int, this still allows attribute names like
        # "1", "2", etc. (which are stored as strings)
        if isinstance(key, int):
            # check to see if attribute exists
            if not self.attrindex.HasBackward(key):
                raise KeyError(f"Attribute number {key} not defined")
            # gets attribute name from number using index
            key = self.attrindex.GetBackward(key)

        return self.attributes[key]

    def __contains__(self, key: Hashable) -> bool:
        """Check if an attribute is defined in the dictionary."""
        # allow checks using attribute number
        if isinstance(key, int):
            return self.attrindex.HasBackward(key)
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
        inline_vendor = False
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
                inline_vendor = True
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

        (name, code, datatype) = tokens[1:4]

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

        if len(codes) == 2:
            code = int(codes[1])
            parent = self.stack.top_attr()[
                self.stack.top_namespace().GetBackward(int(codes[0]))
            ]

            # currently, the presence of a parent attribute means that we are
            # dealing with a TLV, so push the TLV layer onto the stack
            self.stack.push(parent, parent.attrindex)
        elif len(codes) == 1:
            code = int(codes[0])
            parent = None
        else:
            raise ParseError("nested tlvs are not supported")

        datatype = datatype.split("[")[0]

        if datatype not in RADIUS_TYPES:
            raise ParseError(
                "Illegal type: " + datatype, file=state["file"], line=state["line"]
            )

        attribute = Attribute(
            name, code, datatype, parent, vendor, encrypt=encrypt, has_tag=has_tag
        )

        # if detected an inline vendor (vendor in the flags field), set the
        # attribute under the vendor's attributes
        # THIS FUNCTION IS NOT SUPPORTED IN FRv4 AND SUPPORT WILL BE REMOVED
        if inline_vendor:
            self.attributes["Vendor-Specific"][vendor][name] = attribute
        else:
            # add attribute name and number mapping to current namespace
            self.stack.top_namespace().Add(name, code)
            # add attribute to current namespace
            self.stack.top_attr()[name] = attribute
            if parent:
                # add attribute to parent
                parent[name] = attribute
                # must remove the TLV layer when we are done with it
                self.stack.pop()

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
            adef = self.stack.top_attr()[attr]
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
        value = adef.encode(value)
        self.stack.top_attr()[attr].values.Add(key, value)

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

        (name, number) = tokens[1:3]
        self.vendors.Add(name, int(number, 0))
        if "Vendor-Specific" not in self.attributes:
            self.attributes["Vendor-Specific"] = {}
        self.attributes["Vendor-Specific"][name] = Vendor(name, int(number))

    def __ParseBeginVendor(self, state: dict, tokens: list) -> None:
        """Start a block of attributes for a specific vendor."""
        if len(tokens) != 2:
            raise ParseError(
                "Incorrect number of tokens for begin-vendor statement",
                file=state["file"],
                line=state["line"],
            )

        name = tokens[1]

        if not self.vendors.HasForward(name):
            raise ParseError(
                "Unknown vendor %s in begin-vendor statement" % name,
                file=state["file"],
                line=state["line"],
            )

        state["vendor"] = name
        vendor = self.attributes["Vendor-Specific"][name]
        self.stack.push(vendor, vendor.attrindex)

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
        # remove the vendor layer
        self.stack.pop()

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
