# Running a Radius Server

- [UDP Server](#udp)
  - [Handling packets](#handling-packets)
  - [Replying](#replying)
  - [Status-Server](#status-server)
- [RadSec (Radius Over TLS)](#radsec-radius-over-tls)


# UDP

!!! Note
    For a more secure alternative, see the RadSec section below.

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

# Handling packets


!!! note

    You may want to jump ahead to the client section in order to make a test request to your server.

Fundamentally, you subclass the `pyrad2` server and implement the packet
handlers for the roles you enable.

``` py title="Methods you have to implement"
class MyRadiusServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):

    def handle_acct_packet(self, protocol, pkt, addr):
```

CoA and Disconnect are part of RADIUS Dynamic Authorization (RFC 5176). They are
usually received by a NAS or proxy acting as a Dynamic Authorization Server, not
by a normal authentication/accounting server. If you enable the CoA listener
with `enable_coa=True`, you can override these handlers too:

``` py title="Optional Dynamic Authorization handlers"
class MyDynamicAuthorizationServer(ServerAsync):
    def handle_coa_packet(self, protocol, pkt, addr):

    def handle_disconnect_packet(self, protocol, pkt, addr):
```

If you do not override them, PyRad2 responds with `CoA-NAK` or
`Disconnect-NAK` and `Error-Cause = Unsupported-Extension`.

When a packet arrives at these functions it has already been parsed, validated and instantiated into a [pyrad2.packet.Packet](https://github.com/nicholasamorim/pyrad2/blob/master/pyrad2/packet.py) class.

PyRad2 validates `Message-Authenticator` whenever the attribute is present. By
default, incoming packets containing `EAP-Message` must include a valid
`Message-Authenticator`; other packets remain compatible with older clients. To
require it on every incoming packet, pass `require_message_authenticator=True`
when constructing `Server`, `ServerAsync`, or `RadSecServer`.

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

# Replying

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

    reply.code = PacketType.AccessAccept
    protocol.send_response(reply, addr)
```

Lastly, you set the reply code. Reply codes live on the `PacketType` enum in
`pyrad2.constants`:

``` py title="Importing reply codes"
from pyrad2.constants import PacketType

reply.code = PacketType.AccessAccept
```

The most common reply codes are:

| Name | Value |
| --- | --- |
| `PacketType.AccessAccept` | 2 |
| `PacketType.AccessReject` | 3 |
| `PacketType.AccountingResponse` | 5 |
| `PacketType.StatusServer` | 12 |
| `PacketType.StatusClient` | 13 |
| `PacketType.DisconnectACK` | 41 |
| `PacketType.DisconnectNAK` | 42 |
| `PacketType.CoAACK` | 44 |
| `PacketType.CoANAK` | 45 |

See the [constants API reference](api/constants.md) for the complete list.

# Status-Server

PyRad2 handles RFC 5997 Status-Server health checks before dispatching to your
normal authentication or accounting handlers. Status-Server requests must
include a valid `Message-Authenticator`; requests without one are dropped.

When a Status-Server packet arrives on the authentication port, the server
responds with `Access-Accept`. When it arrives on the accounting port, the
server responds with `Accounting-Response`. These replies do not run your
authentication or accounting side effects.

# RadSec (Radius Over TLS)

## Overview

!!! Note
    
    This feature implements [RFC 6614](https://datatracker.ietf.org/doc/html/rfc6614) and it's currently *experimental*.

Generally speaking, the content of the RFC is simple.
RADIUS is experiencing several shortcomings, such as its dependency on the unreliable transport protocol UDP and the lack of security for large parts of its packet payload. RADIUS security is based on the MD5 algorithm, which has been proven to be insecure.

RADSEC effectively means performing communications over TCP instead of UDP (generally on port 2083) and use TLS as a security layer.

RADSEC is the same as “Radius Over TLS” or Radius/TLS.

The default destination port number for RADIUS over TLS is TCP/2083 and **there are no separate ports** for authentication, accounting, and dynamic authorization changes. All the routing for packet handling is done internally.

The RadSec server and client follow the RFC and sets the default shared secret to `radsec`.

## Running a RadSec Server

We provide an [example implementation](https://github.com/nicholasamorim/pyrad2/blob/master/examples/server_radsec.py) in our examples folder. You can download it and place on your project folder.

*Test* SSL certificates can be downloaded from the [certs folder](https://github.com/nicholasamorim/pyrad2/blob/master/examples/certs/).

The principle is the same as the classic UDP server, except RadSec carries all
packet types over the same TLS/TCP listener. You inherit from the base class and
implement authentication and accounting handlers. Dynamic Authorization handlers
are optional; by default, unsupported CoA or Disconnect requests receive NAK
responses.

``` py title="RadSec Server"
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer

class RadSecServer(BaseRadSecServer):
    # You must implement these two methods
    async def handle_access_request(self, packet: AuthPacket):
        pass
    
    async def handle_accounting(self, packet: AcctPacket):
        pass

    # Override these only when acting as a Dynamic Authorization Server
    async def handle_disconnect(self, packet: CoAPacket):
        pass
    
    async def handle_coa(self, packet: CoAPacket):
        pass

async def main():
    hosts = {
        "127.0.0.1": RemoteHost(name="localhost", address="127.0.0.1", secret=b"radsec")
    }

    THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))
    server = RadSecServer(
        hosts=hosts,
        dictionary=Dictionary(THIS_FOLDER + "/dictionary"),
        certfile=THIS_FOLDER + "/certs/server/server.cert.pem",
        keyfile=THIS_FOLDER + "/certs/server/server.key.pem",
        ca_certfile=THIS_FOLDER + "/certs/ca/ca.cert.pem",
    )

    await server.run()

if __name__ == "__main__":
    asyncio.run(main())
```

!!! Note
    
    RadSec server is only available in async form.

Running this file shows us the server ready to accept requests.

```
2026-05-16 22:18:35.415 | INFO | pyrad2.radsec.server:run:101 - RADSEC Server with mutual TLS running on ('0.0.0.0', 2083)
```

RadSec Status-Server health checks use the same TLS/TCP connection as other
RadSec packets. To check the example RadSec server, run:

```bash
PYTHONPATH=. uv run examples/status_radsec.py
```

The UDP `examples/status.py` script only talks to normal RADIUS servers on
UDP/1812 or UDP/1813.
