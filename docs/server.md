# Running a Radius Server

- [UDP Server](#udp-server)
  - [Handling packets](#handling-packets)
  - [Replying](#replying)
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

The princinple is the same as the classic UDP server. You inherit from the base class and implement four methods.

``` py title="RadSec Server"
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer

class RadSecServer(BaseRadSecServer):
    # You must implement these four methods
    async def handle_access_request(self, packet: AuthPacket):
        pass
    
     async def handle_accounting(self, packet: AcctPacket):
        pass

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
2025-07-09 16:18:35.415 | INFO | pyrad2.radsec.server:run:86 - RADSEC Server with mutual TLS running on ('0.0.0.0', 2083)
2025-07-09 16:18:35.415 | INFO | pyrad2.radsec.server:run:87 - Allowed ciphers: DES-CBC3-SHA:RC4-SHA:AES128-SHA
```