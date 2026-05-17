# Running a Radius Server

- [UDP Server](#udp)
  - [Handling packets](#handling-packets)
  - [Replying](#replying)
  - [Status-Server](#status-server)
  - [Duplicate detection (RFC 5080)](#duplicate-detection-rfc-5080)
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

# Duplicate detection (RFC 5080)

UDP loses packets. Clients retransmit. [RFC 5080 §2.2.2](https://datatracker.ietf.org/doc/html/rfc5080#section-2.2.2) requires servers to **detect duplicates and resend the original reply instead of re-running the handler**. That matters most for EAP: each Access-Challenge carries a fresh `State` attribute, and re-processing a retransmission would issue a new `State` that breaks the conversation. It also matters for accounting (avoid double counting) and CoA/Disconnect (avoid double-applying authorization changes).

Both `Server` and `ServerAsync` enable this by default. The key is the RFC-mandated tuple `(source IP, source UDP port, code, Identifier, Request Authenticator)`. Retransmissions of:

- Access-Request
- Accounting-Request
- CoA-Request
- Disconnect-Request

receive the byte-identical cached reply for `dedup_ttl` seconds (default 30s); your handler runs exactly once. Duplicates that arrive while the original is still being processed are dropped silently — exactly what the RFC requires.

You can tune or disable it via constructor arguments:

``` py title="Tuning the dedup cache"
from pyrad2.server_async import ServerAsync

server = ServerAsync(
    # ... your usual kwargs ...
    dedup_enabled=True,        # default
    dedup_ttl=30.0,            # seconds a cached reply stays valid
    dedup_max_entries=4096,    # LRU cap before old entries get evicted
)
```

Pass `dedup_enabled=False` to opt out entirely, or pass `dedup_cache=...` (a `pyrad2.dedup.ResponseCache` instance) to share one cache across servers or inject a custom clock for tests.

Status-Server requests, CoA/Disconnect-NAK replies, and packets where the parsed source doesn't match an allowed `RemoteHost` are never cached.

!!! Note

    RadSec runs over TCP/TLS, where the transport already handles retransmission of lost segments. RFC 5080 §2.2.2 targets UDP specifically and the dedup cache is therefore **not** wired into `RadSecServer`.

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

## RADIUS/1.1 (RFC 9765)

!!! Warning

    Experimental. The RFC was published in April 2025 and ecosystem support is still small.

[RFC 9765](https://datatracker.ietf.org/doc/html/rfc9765) defines **RADIUS/1.1**, a TLS-only profile that drops the MD5 baggage now that TLS already provides authentication, integrity, and confidentiality on the wire. On the same RadSec port (2083), the two sides negotiate the protocol version via TLS ALPN:

| ALPN string | Profile |
| --- | --- |
| `radius/1.0` | Historic RADIUS (RFC 2865), MD5-based |
| `radius/1.1` | RFC 9765 — no MD5, no Message-Authenticator, Token instead of Request Authenticator |

What changes once v1.1 is negotiated:

- **No MD5 obfuscation** of `User-Password`, `Tunnel-Password`, or `MS-MPPE-*-Key` — they flow as plain `string` over the TLS connection (§5.1.1, §5.1.3, §5.1.4). In your handler, `packet["User-Password"]` is the literal cleartext bytes the client sent.
- **No Message-Authenticator.** Sending one is forbidden (§5.2); any instance received is silently discarded.
- **Token in place of Request Authenticator.** The first 4 bytes of the 16-byte authenticator slot become a per-connection 32-bit counter (§4.1); the remaining 12 are zero. Replies echo the same Token. The on-wire packet layout is otherwise unchanged.
- **Identifier byte is zero on the wire** (§4.1, Reserved-1). Request/response matching uses the Token.
- **All MD5-based verifiers short-circuit** (`verify_packet`, `verify_auth_request`, `verify_acct_request`, `verify_coa_request`) — TLS already authenticated the bytes.

### Enabling RADIUS/1.1

Pass `radius_versions=...` to the server constructor — the same kwarg exists on `RadSecClient`. Defaults to `(V1_0,)` on both sides for backward compatibility with existing deployments: no ALPN string is advertised when only v1.0 is requested, so historic peers see byte-identical TLS hellos.

```py title="Advertising both v1.0 and v1.1"
from pyrad2.radsec.server import RadSecServer
from pyrad2.radsec.v11 import RadiusVersion

server = RadSecServer(
    # ... your usual kwargs ...
    radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
)
```

Negotiation outcome:

| Server advertises | Client advertises | Result |
| --- | --- | --- |
| `(V1_0,)` | `(V1_0,)` | v1.0 (no ALPN sent — identical to historic RadSec) |
| `(V1_0, V1_1)` | `(V1_0, V1_1)` | **v1.1** — highest mutually supported wins |
| `(V1_0,)` | `(V1_0, V1_1)` | v1.0 (server silent on ALPN, client falls back) |
| `(V1_0, V1_1)` | `(V1_0,)` | v1.0 (client silent on ALPN, server falls back) |
| `(V1_1,)` | `(V1_0,)` | **Connection closed** — server refuses to downgrade (RFC 9765 §3.3) |
| `(V1_0,)` | `(V1_1,)` | Client raises `PacketError` and the call returns `None` — refuses to downgrade |
| `(V1_1,)` | `(V1_1,)` | v1.1 (or TLS alert 120 if either side rejects the other's certs) |

A connection is closed/rejected exactly when one side is configured *only* for v1.1 and the other side didn't advertise the `radius/1.1` ALPN. RFC 9765 §3.4 also mandates **TLS 1.3 or later** whenever v1.1 is in play — `RadSecServer` and `RadSecClient` automatically promote `minimum_tls_version` to `TLSv1_3` if v1.1 is configured.

Once a connection is established, the negotiated version is available as `client._negotiated_version` (client side) and on every parsed packet as `packet.radius_version`. The RadSec server logs `RADSEC connection established from ... (ALPN=..., RADIUS/...)` on every handshake.

### Writing a v1.1-aware handler

Existing handlers work unchanged. On the receive side, in v1.1 the `User-Password` attribute is already in plaintext (TLS authenticated the bytes, so no obfuscation is needed); in v1.0 it's obfuscated and you call `pw_decrypt` as before:

```py title="Cross-version handler"
async def handle_access_request(self, packet):
    if packet.radius_version == RadiusVersion.V1_1:
        password = packet["User-Password"][0]          # plain string
    else:
        password = packet.pw_decrypt(packet[2][0])     # raw bytes → str
    reply = packet.create_reply()
    reply.code = PacketType.AccessAccept
    return reply
```

The reply path is fully automatic — `create_reply()` propagates `radius_version` and the Token to the reply, and `reply_packet()` skips MD5 / Message-Authenticator when v1.1 is set.

### Sending passwords from clients that advertise both versions

A client that advertises both `radius/1.0` and `radius/1.1` doesn't know which one will be negotiated until the TLS handshake completes — but attribute assignment happens before that. Use `Packet.set_obfuscated()` to defer the encoding decision until send time:

```py title="Version-agnostic password assignment"
req = client.create_auth_packet(User_Name="alice")
# Stores plaintext; pw_crypt() is applied at send time if v1.0 is
# negotiated, or emitted as plain bytes if v1.1 wins.
req.set_obfuscated("User-Password", "hunter2")
reply = await client.send_packet(req)
```

The same helper works for `Tunnel-Password` and other `encrypt=2` attributes, where direct assignment also runs into the assignment-vs-handshake ordering problem.
