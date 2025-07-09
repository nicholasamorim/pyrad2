class RadiusException(Exception):
    pass


class ServerPacketError(RadiusException):
    """Exception class for bogus packets.
    ServerPacketError exceptions are only used inside the Server class to
    abort processing of a packet.
    """

    pass


class Timeout(RadiusException):
    """Simple exception class which is raised when a timeout occurs
    while waiting for a RADIUS server to respond."""

    pass


class PacketError(RadiusException):
    """Raised when the packet is invalid."""

    pass


class ParseError(RadiusException):
    """Exception raised for errors
    while parsing RADIUS dictionary files.

    Attributes:
        msg (str): Error message
        linenumber (int): Line number on which the error occurred
    """

    def __init__(self, msg=None, **data):
        self.msg = msg
        self.file = data.get("file", "")
        self.line = data.get("line", -1)

    def __str__(self):
        str = ""
        if self.file:
            str += self.file
        if self.line > -1:
            str += "(%d)" % self.line
        if self.file or self.line > -1:
            str += ": "
        str += "Parse error"
        if self.msg:
            str += ": %s" % self.msg

        return str
