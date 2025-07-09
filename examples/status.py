#!/usr/bin/python
import sys

from loguru import logger

from pyrad2.client import Client
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import Timeout
from pyrad2.constants import PacketType


srv = Client(
    server="127.0.0.1", authport=18121, secret=b"test", dict=Dictionary("dictionary")
)

req = srv.CreateAuthPacket(code=PacketType.StatusServer)
req["FreeRADIUS-Statistics-Type"] = "All"
req.add_message_authenticator()

try:
    logger.info("Sending FreeRADIUS status request")
    reply = srv.SendPacket(req)
except Timeout:
    logger.error("RADIUS server does not reply")
    sys.exit(1)
except OSError as error:
    logger.error("Network error: {}", error[1])
    sys.exit(1)

print("Attributes returned by server:")
for i in reply.keys():
    logger.info("{}: {}", i, reply[i])
