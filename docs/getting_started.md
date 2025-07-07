# Getting started

!!! note

    This guide is a work in progress.

- [How does pyrad2 work](#how-does-pyrad2-work)
    - [RADIUS Concepts](#radius-concepts)
        - [Dictionary](#dictionary)
- [RADIUS Server](#radius-server)
    - [Handling packets](#handling-packets)
    - [Replying](#replying)
- [RADIUS Client](#radius-server)
    - [Sending an authentication packet](#sending-an-authentication-packet)
- [Setting attributes](#setting-attributes)
  
  
``` bash title="Install with pip"
$ pip install pyrad2
```

``` bash title="Install with uv"
$ uv add pyrad2
```

# How does pyrad2 work

pyrad2 allows you to build servers and clients for the [RADIUS](https://en.wikipedia.org/wiki/RADIUS) protocol.

It is not meant to be a standalone implementation like [FreeRADIUS](https://freeradius.org), but rather as a tool to allow you to build your own server and client.

## RADIUS Concepts

### Dictionary 

For the purpose of using pyrad2, the most important concept is the _Dictionary_. The dictionary is an actual file on the filesystem.

!!! note

    Dictionary files are textfiles with one command per line.

RADIUS uses dictionaries to define the attributes that can
be used in packets. The Dictionary class stores the attribute definitions from one or more dictionary files and allows Server/Client to understand what an _attribute code_ means.

Here's an example of how it looks:

```
ATTRIBUTE	User-Name		    1	string
ATTRIBUTE	User-Password		2	string
ATTRIBUTE	CHAP-Password		3	octets
```

You can find a reference dictionary file [here](https://github.com/nicholasamorim/pyrad2/blob/master/examples/dictionary). Another dictionary is provided [here](https://github.com/nicholasamorim/pyrad2/blob/master/examples/dictionary.freeradius) with FreeRADIUS vendor-specific attributes.

For our example, download _both files_ and place it into your project folder.

When you see code like this:

``` py title="Loading a dictionary"
dictfile = dictionary.Dictionary("dictionary")
```

You are actually passing a _path_ to a file (or a [file-like object](https://docs.python.org/3/library/io.html)) called `dictionary`, so make sure the file you pass is accessible from your code and it's a valid dictionary file.

# RADIUS Server

There are two ways of running a server: [sync](https://github.com/nicholasamorim/pyrad2/blob/master/examples/server.py) or [async](https://github.com/nicholasamorim/pyrad2/blob/master/examples/server_async.py). 

Pick an implementation above and copy the code into your project. This should just work now if you have already installed `pyrad2`:

``` bash title="Running the example server"
uv run server_async.py
```

You should see the logs:

```
2025-07-07 12:38:19.929 | INFO | pyrad2.server_async:connection_made:57 - [127.0.0.1:1812] Transport created
2025-07-07 12:38:19.929 | INFO | pyrad2.server_async:connection_made:57 - [127.0.0.1:1813] Transport created
2025-07-07 12:38:19.929 | INFO | pyrad2.server_async:connection_made:57 - [127.0.0.1:3799] Transport created
```

!!! Warning

    Sync support _may_ be dropped in the future. We strongly recommend you use the async version.

## Handling packets


!!! note

    You may want to jump ahead to the client section in order to make a test request to your server.

Fundamentally, you have to subclass the `pyrad2` server and implement four methods.

``` py title="Methods you have to implement"
class MyRadiusServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):

    def handle_acct_packet(self, protocol, pkt, addr):

    def handle_coa_packet(self, protocol:, pkt, addr):

    def handle_disconnect_packet(self, protocol, pkt, addr):
```

When a packet arrives at these functions it has already been parsed, validated and instantiated into a [pyrad2.packet.Packet](https://github.com/nicholasamorim/pyrad2/blob/master/pyrad2/packet.py) class.

The example implementation provided *simply logs* details of the request it has just received and it's meant to illustrate the contents of the packet being received.

``` py
def handle_auth_packet(self, protocol, pkt, addr):
    logger.info("Received an authentication request with id {}", pkt.id)
    logger.info("Authenticator {}", pkt.authenticator.hex())
    logger.info("Secret {}", pkt.secret)
    logger.info("Attributes: ")
    for attr in pkt.keys():
        logger.info("{}: {}", attr, pkt[attr])
```

## Replying

To reply a packet, you must create a reply packet using `self.create_reply_packet`. The first argument is the packet you received and you can pass keyword arguments to populate the reply packet.

``` py title="Replying"
def handle_auth_packet(self, protocol, pkt, addr):
    ...
    reply = self.create_reply_packet(
        pkt,
        **{
            "Service-Type": "Framed-User",
            "Framed-IP-Address": "192.168.0.1",
            "Framed-IPv6-Prefix": "fc66::1/64",
        },
    )

    reply.code = AccessAccept
    protocol.send_response(reply, addr)
```

Lastly, you set the reply code. Possible reply codes can be imported from `pyrad2.packet`.

``` py title="Reply constants in pyrad2.packet"
AccessAccept = 2
AccessReject = 3
AccountingResponse = 5
StatusServer = 12
StatusClient = 13
DisconnectACK = 41
DisconnectNAK = 42
CoAACK = 44
CoANAK = 45
```

# RADIUS Client

To instantiate a client you can use `ClientAsync`. A sync version is also provided in `pyrad2.client`.

!!! Note

    Both your server and client must be loaded with the _same_ dictionary. Remember, this is how the client and server can understand what it means to use a given attribute code.


``` py title="Instantiating a client"
from pyrad2.client_async import ClientAsync
from pyrad2.dictionary import Dictionary


client = ClientAsync(
    server="localhost",
    secret=b"Kah3choteereethiejeimaeziecumi",
    timeout=4,
    dict=Dictionary("dictionary"),
)
```

!!! Note

    In real code, we would never pass the secret hardcoded.

## Sending an authentication packet

You can find the example for an auth request [here](https://github.com/nicholasamorim/pyrad2/blob/master/examples/auth_async.py).

``` bash title="Making an authentication request"
$ uv run auth_async.py  # make sure the server is running before

2025-07-07 13:06:36.984 | INFO     | pyrad2.client_async:connection_made:112 - [localhost:3799] Transport created with binding in ::1:62525
2025-07-07 13:06:36.984 | INFO     | pyrad2.client_async:connection_made:112 - [localhost:1812] Transport created with binding in 127.0.0.1:8000
2025-07-07 13:06:36.984 | INFO     | pyrad2.client_async:connection_made:112 - [localhost:1813] Transport created with binding in ::1:64970
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:87 - Access accepted
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:91 - Attributes returned by server:
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:93 - Service-Type: ['Framed-User']
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:93 - Framed-IP-Address: ['192.168.0.1']
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:93 - Framed-IPv6-Prefix: ['fc66::/64']
```

This is the core code that creates the packet.  

``` py
def create_request(client, user):
    req = client.CreateAuthPacket(User_Name=user)

    req["NAS-IP-Address"] = "192.168.1.10"
    req["NAS-Port"] = 0
    req["Service-Type"] = "Login-User"
    req["NAS-Identifier"] = "trillian"
    req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
    req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
    req["Framed-IP-Address"] = "10.0.0.100"

    return req
```

You can find a list of standard RADIUS attributes [here](https://datatracker.ietf.org/doc/html/rfc2865#page-22). Note that these do not include vendor-specific attributes.

# Setting attributes

To set attributes in the `Client` object, you need to replace underscores with hyphens. So instead of `User_Name`, you use `User-Name`. The former is used in python code and the latter is used directly in the underlying data.

``` py title="Naming inconsistencies"
req = srv.CreateAuthPacket(User_Name="wichert")

# But if acessing the attributes directly
req["User-Name"] = "wichert2"
req["NAS-IP-Address"] = "192.168.1.10"

```


[Suggestion]: Add some description for the valid arguments that could be passed to CreateAuthPacket.
