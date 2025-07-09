#!/usr/bin/python
import random
import sys

from pyrad2.client import Client
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import Timeout

from loguru import logger


def SendPacket(srv, req):
    try:
        srv.SendPacket(req)
    except Timeout:
        logger.info("RADIUS server does not reply")
        sys.exit(1)
    except OSError as error:
        logger.error("Network error: {}", error[1])
        sys.exit(1)


srv = Client(
    server="127.0.0.1",
    secret=b"Kah3choteereethiejeimaeziecumi",
    dict=Dictionary("dictionary"),
)

req = srv.CreateAuthPacket(User_Name="wichert")

req["NAS-IP-Address"] = "192.168.1.10"
req["NAS-Port"] = 0
req["Service-Type"] = "Framed-User"
req["NAS-Identifier"] = "trillian"
req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
req["Framed-IP-Address"] = "10.0.0.100"

logger.info("Sending accounting start packet")
req["Acct-Status-Type"] = "Start"
srv.SendPacket(req)

logger.info("Sending accounting stop packet")
req["Acct-Status-Type"] = "Stop"
req["Acct-Input-Octets"] = random.randrange(2**10, 2**30)
req["Acct-Output-Octets"] = random.randrange(2**10, 2**30)
req["Acct-Session-Time"] = random.randrange(120, 3600)
req["Acct-Terminate-Cause"] = random.choice(["User-Request", "Idle-Timeout"])
srv.SendPacket(req)
