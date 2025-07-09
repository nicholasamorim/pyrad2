#!/usr/bin/python
import sys

from loguru import logger

from pyrad2.client import Client
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import Timeout

srv = Client(
    server="127.0.0.1",
    secret=b"Kah3choteereethiejeimaeziecumi",
    dict=Dictionary("dictionary"),
)

req = srv.CreateAuthPacket(User_Name="wichert")

req["NAS-IP-Address"] = "192.168.1.10"
req["NAS-Port"] = 0
req["Service-Type"] = "Login-User"
req["NAS-Identifier"] = "trillian"
req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
req["Framed-IP-Address"] = "10.0.0.100"

try:
    logger.info("Sending authentication request")
    reply = srv.SendPacket(req)
except Timeout:
    logger.error("RADIUS server does not reply")
    sys.exit(1)
except OSError as error:
    logger.inferroro("Network error: {}", error[1])
    sys.exit(1)

if reply.code == PacketType.AccessAccept:
    logger.info("Access accepted")
else:
    logger.error("Access denied")

logger.info("Attributes returned by server:")
for i in reply.keys():
    logger.info("{}: {}", i, reply[i])
