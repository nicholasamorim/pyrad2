from pyrad2.bidict import BiDict

from .attribute import Attribute


class Vendor:
    """Class representing a vendor with its attributes.

    The existence of this class allows us to have a namespace for vendor
    attributes. If vendor was only represented by an int or string in the
    Vendor-Specific attribute (i.e., Vendor-Specific = { 16 = [ foo ] }), it is
    difficult to have a nice namespace mapping of vendor attribute names to
    codes.
    """

    def __init__(self, name: str, code: int):
        """
        @param name: name of the vendor
        @param code: vendor ID
        """
        self.name = name
        self.code = code

        self.attributes: dict = {}
        self.attrindex = BiDict()

    def __getitem__(self, key: str | int) -> Attribute:
        # if using attribute number, first convert to attribute name
        if isinstance(key, int):
            if not self.attrindex.HasBackward(key):
                raise KeyError(f"Non existent attribute {key}")
            key = self.attrindex.GetBackward(key)

        # return the attribute by name
        return self.attributes[key]

    def __setitem__(self, key: str, value: Attribute):
        # key must be the attribute's name
        if key != value.name:
            raise ValueError("Key must be equal to Attribute name")

        # update both the attribute and index dicts
        self.attributes[key] = value
        self.attrindex.Add(value.name, value.code)
