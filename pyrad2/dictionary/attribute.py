from typing import Any

from pyrad2.bidict import BiDict
from pyrad2.datatypes import RADIUS_TYPES
from pyrad2.datatypes.base import AbstractDataType
from pyrad2.datatypes.structural import AbstractStructural
from pyrad2.datatypes.types import AbstractType


class Attribute:
    """Represents a RADIUS attribute.

    Attributes:
        name (str): Attribute name
        code (int): RADIUS code
        type (str): Data type (e.g., 'string', 'ipaddr')
        vendor (int): Vendor ID (0 if standard)
        has_tag (bool): Whether attribute supports tags
        encrypt (int): Encryption type (0 = none)
        values (BiDict): Mapping of named values to their codes
    """

    def __init__(
        self,
        name: str,
        code: int,
        datatype: str,
        parent=None,
        vendor=None,
        values=None,
        encrypt: int = 0,
        has_tag: bool = False,
    ):
        if datatype not in RADIUS_TYPES:
            raise ValueError("Invalid data type")

        self.name = name
        self.code = code
        self.type: AbstractType | AbstractDataType = RADIUS_TYPES[datatype]
        self.parent = parent
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = has_tag

        self.values = BiDict()
        if values:
            for key, value in values.items():
                self.values.Add(key, value)

        self.children: dict = {}
        # bidirectional mapping of children name <-> numbers for the namespace
        # defined by this attribute
        self.attrindex = BiDict()

    def encode(self, decoded: Any, *args, **kwargs) -> bytes:
        """
        encodes value with attribute datatype
        @param decoded: value to encode
        @type decoded: any
        @param args:
        @param kwargs:
        @return: encoding of object
        @rtype: bytes
        """
        return self.type.encode(self, decoded, args, kwargs)

    def decode(self, raw: bytes | dict) -> Any:
        """decodes bytestring or dictionary with attribute datatype.

        Args:
            raw (bytes | dict): value to decode

        Returns:
            Any: Python data structure
        """
        #  Use datatype.decode to decode leaf attributes
        if isinstance(raw, bytes):
            # precautionary check to see if the raw data is truly being held
            # by a leaf attribute
            if isinstance(self.type, AbstractStructural):
                raise ValueError("Structural datatype holding string!")
            if hasattr(self.type, "decode"):
                return self.type.decode(raw)
            else:
                raise RuntimeError(f"Attribute does not have decode: {self.type}")

        #  Recursively calls sub attribute's .decode() until a leaf attribute
        #  is reached
        for sub_attr, value in raw.items():
            raw[sub_attr] = self.children[sub_attr].decode(value)
        return raw

    def get_value(self, packet: bytes, offset: int) -> tuple[Any, int]:
        """Gets encapsulated value from attribute

        Args:
            packet (bytes): Packet in bytestring
            offset (int): Cursor where current attribute starts in packet

        Returns:
            Any: Encapsulated value, bytes read
        """
        return self.type.get_value(self, packet, offset)

    def __getitem__(self, key) -> Any:
        if isinstance(key, int):
            if not self.attrindex.HasBackward(key):
                raise KeyError(f"Missing attribute {key}")
            key = self.attrindex.GetBackward(key)
        if key not in self.children:
            raise KeyError(f"Non-existent sub attribute {key}")
        return self.children[key]

    def __setitem__(self, key: str, value: "Attribute") -> Any:
        if key != value.name:
            raise ValueError("Key must be equal to Attribute name")
        self.children[key] = value
        self.attrindex.Add(key, value.code)


class AttributeStack:
    """
    class representing the nested layers of attributes in dictionaries
    """

    def __init__(self):
        self.attributes = []
        self.namespaces = []

    def push(self, attr: Attribute, namespace: BiDict) -> None:
        """Pushes an attribute and a namespace onto the stack
        Currently, the namespace will always be the namespace of the attribute
        that is passed in. However, for future considerations (i.e., the group
        datatype), we have somewhat redundant code here.

        Args:
            attr (Attribute): Attribute to add children to
            namespace (BiDict): Namespace
        """
        self.attributes.append(attr)
        self.namespaces.append(namespace)

    def pop(self) -> None:
        """
        removes the top most layer
        @return: None
        """
        del self.attributes[-1]
        del self.namespaces[-1]

    def top_attr(self) -> Attribute:
        """
        gets the top most attribute
        @return: attribute
        """
        return self.attributes[-1]

    def top_namespace(self) -> BiDict:
        """
        gets the top most namespace
        @return: namespace
        """
        return self.namespaces[-1]


class NamespaceStack:
    """
    represents a FIFO stack of attribute namespaces
    """

    def __init__(self):
        self.stack = []

    def push(self, namespace: Any) -> None:
        """
        pushes namespace onto stack
        namespace objects must implement __getitem__(key) that takes in either
        a string or int and returns an Attribute or dict instance
        :param namespace: new namespace
        :return:
        """
        self.stack.append(namespace)

    def pop(self) -> None:
        """
        pops the top most namespace from the stack
        :return: None
        """
        del self.stack[-1]

    def top(self) -> Any:
        """
        returns the top-most namespace in the stack
        :return: namespace
        """
        return self.stack[-1]
