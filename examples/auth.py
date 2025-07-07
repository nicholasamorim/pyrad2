#!/usr/bin/python
from pyrad2.client import Client
from pyrad2.dictionary import Dictionary
import sys
import pyrad2.packet

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
    print("Sending authentication request")
    reply = srv.SendPacket(req)
except pyrad2.client.Timeout:
    print("RADIUS server does not reply")
    sys.exit(1)
except OSError as error:
    print("Network error: " + error[1])
    sys.exit(1)

if reply.code == pyrad2.packet.AccessAccept:
    print("Access accepted")
else:
    print("Access denied")

print("Attributes returned by server:")
for i in reply.keys():
    print("{}: {}".format(i, reply[i]))
