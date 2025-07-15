from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyrad2.dictionary import Attribute, Dictionary


class AbstractDataType(ABC):
    """
    Root of entire datatype class hierarchy
    """

    def __init__(self, name: str):
        """
        Args:
            name (str): representation of datatype
        """
        self.name = name

    @abstractmethod
    def encode(self, attribute: "Attribute", decoded: Any, *args, **kwargs) -> bytes:
        """
        python data structure into bytestring
        :param attribute: dictionary attribute
        :type attribute: pyrad.dictionary.Attribute class
        :param decoded: decoded value
        :type decoded: any
        :param args:
        :param kwargs:
        :return: bytestring encoding
        :rtype: bytes
        """

    @abstractmethod
    def print(self, attribute: "Attribute", decoded: Any, *args, **kwargs):
        """Conver python data structure into string

        :param attribute: dictionary attribute
        :type attribute: pyrad.dictionary.Attribute class
        :param decoded: decoded value
        :type decoded: any
        :param args:
        :param kwargs:
        :return: string representation
        :rtype: str
        """

    @abstractmethod
    def parse(self, dictionary: "Dictionary", string: str, *args, **kwargs) -> Any:
        """Parse python data structure from string.


        Args:
            dictionary (Dictionary): RADIUS dictionary
            string (str): String representation of an object

        Returns:
            any: Python data strucuture
        """

    @abstractmethod
    def get_value(
        self, attribute: "Attribute", packet: bytes, offset: int
    ) -> tuple[Any, int]:
        """Gets encapsulated value

        returns a tuple of encapsulated value and an int of number of bytes
        read. the tuple contains one or more (key, value) pairs, with each key
        being a full OID (tuple of ints) and the value being a bytestring (for
        leaf attributes), or a dict (for TLVs).

        Future work will involve the removal of the dictionary and code
        arguments. they are currently needed for VSA's get_value() where both
        values are needed to fetch vendor attributes since vendor attributes
        are not stored as a sub-attribute of the Vendor-Specific attribute.

        future work will also change the return value. in place of returning a
        tuple of (key, value) pairs, a single bytestring or dict will be
        returned.

        Args:
            attribute (pyrad2.dictionary.Attribute): Attribute
            packet (packet.Packet): Entire packet bytestring
            offset (int): Position in packet where current attribute begins

        Returns:
            any: Encapsulated value, bytes read
        """
