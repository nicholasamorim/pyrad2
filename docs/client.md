# Making RADIUS Requests

- [Making RADIUS Requests](#making-radius-requests)
- [UDP Requests](#udp)
  - [Sending an authentication packet](#sending-an-authentication-packet)
- [Status-Server health checks](#status-server-health-checks)
- [Setting attributes](#setting-attributes)
- [RadSec](#radsec)



# UDP

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
    req = client.create_auth_packet(User_Name=user)

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

## EAP-MD5

The sync and async UDP clients both handle the EAP-MD5 challenge round-trip
transparently. Pass `auth_type="eap-md5"` when constructing the
`AuthPacket` and `User-Password`; the client injects an EAP-Identity, and
on an `Access-Challenge` response it computes the MD5 challenge response,
copies the server's `State`, and re-sends — surfacing only the final
`Access-Accept` / `Access-Reject`.

```py title="Async EAP-MD5 request"
req = client.create_auth_packet(
    User_Name="alice",
    User_Password="hunter2",
    auth_type="eap-md5",
)
reply = await client.send_packet(req)
```

## Message-Authenticator

PyRad2 validates reply `Message-Authenticator` attributes whenever they are
present. If you construct an `Access-Request` with `EAP-Message`, the sync and
async UDP clients automatically add `Message-Authenticator` before sending it.

Use `enforce_ma=True` when the client should also require replies to include a
valid `Message-Authenticator`:

```py
client = ClientAsync(
    server="localhost",
    secret=b"Kah3choteereethiejeimaeziecumi",
    timeout=4,
    dict=Dictionary("dictionary"),
    enforce_ma=True,
)
```

# Status-Server health checks

Use `create_status_packet()` and `send_status_packet()` for RFC 5997
Status-Server health checks. PyRad2 automatically includes the mandatory
`Message-Authenticator` on the request.

```py title="Sync UDP Status-Server request"
from pyrad2.client import Client

client = Client(...)
req = client.create_status_packet()
reply = client.send_status_packet(req, port="auth")
```

```py title="Async UDP Status-Server request"
from pyrad2.client_async import ClientAsync

client = ClientAsync(...)
req = client.create_status_packet()
reply = await client.send_status_packet(req, port="auth")
```

Use `port="acct"` to check the accounting port instead. Authentication-port
checks expect an `Access-Accept` response; accounting-port checks expect an
`Accounting-Response`.

For a RadSec server, use the TLS/TCP Status-Server example instead:

```bash
PYTHONPATH=. uv run examples/status_radsec.py
```

# Setting attributes

To set attributes in the `Client` object, you need to replace underscores with hyphens. So instead of `User_Name`, you use `User-Name`. The former is used in python code and the latter is used directly in the underlying data.

``` py title="Naming inconsistencies"
req = srv.create_auth_packet(User_Name="wichert")

# But if acessing the attributes directly
req["User-Name"] = "wichert2"
req["NAS-IP-Address"] = "192.168.1.10"

```


[Suggestion]: Add some description for the valid arguments that could be passed to CreateAuthPacket.


# RadSec

!!! Note

    This feature is currently *experimental*.

To use RadSec client, you must import from `pyrad2.radsec.client`.

``` py title="Creating a RadSec client"
client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=Dictionary("/dictionary"),
    certfile="certs/client/client.cert.pem",
    keyfile="certs/client/client.key.pem",
    certfile_server="certs/ca/ca.cert.pem",
)
```

You can find an example implementation [here](https://github.com/nicholasamorim/pyrad2/blob/master/examples/auth_radsec.py).

RadSec uses TLS/TCP on port 2083, so the UDP `examples/status.py` health-check
script will not reach a RadSec server. Use
`examples/status_radsec.py` for RadSec Status-Server health checks.

## RADIUS/1.1 (RFC 9765)

!!! Warning

    Experimental.

`RadSecClient` accepts the same `radius_versions=...` kwarg as the server. The default `(V1_0,)` advertises no ALPN string at all, so handshakes are byte-identical to historic RadSec. Pass `(V1_0, V1_1)` to offer both — the server picks the highest mutually supported version.

```py title="Opting into RADIUS/1.1"
from pyrad2.radsec.client import RadSecClient
from pyrad2.radsec.v11 import RadiusVersion

client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=Dictionary("dictionary"),
    certfile="certs/client/client.cert.pem",
    keyfile="certs/client/client.key.pem",
    certfile_server="certs/ca/ca.cert.pem",
    radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
)

req = client.create_auth_packet(User_Name="alice")
# set_obfuscated defers encoding until send time: pw_crypt() if v1.0 is
# negotiated, plain bytes if v1.1 wins. Necessary when both ALPN values
# are advertised — direct ``req["User-Password"] = pw_crypt(...)`` would
# bake in v1.0 encoding before the TLS handshake even starts.
req.set_obfuscated("User-Password", "hunter2")
reply = await client.send_packet(req)

print(client._negotiated_version)  # RadiusVersion.V1_1 if both sides agreed
```

`set_obfuscated` is the safe choice for both `encrypt=1` (User-Password) and `encrypt=2` (Tunnel-Password, MS-MPPE keys) attributes — including vendor-specific ones, which the deferred path correctly wraps in Vendor-Specific (RADIUS attribute 26). Pass `str` for `string`-typed attributes (`User-Password`, `Tunnel-Password`) and `bytes` for `octets`-typed attributes (`MS-MPPE-Recv-Key`, `MS-MPPE-Send-Key`). For v1.0-only clients you can still use the historic `req["User-Password"] = req.pw_crypt("...")` pattern.

If your client is configured for `(V1_1,)` only and the server doesn't advertise the `radius/1.1` ALPN, `send_packet()` returns `None` after raising `PacketError` internally — the client refuses to silently downgrade per RFC 9765 §3.3. To distinguish that case from a normal timeout, check `client.last_error` after a `None` return: a strict-mode refusal sets it to a `PacketError` whose message contains "No common RADIUS protocol"; a timeout leaves it as the underlying `TimeoutError`; a clean no-reply leaves it `None`.

RadSec also requires TLS 1.3+ whenever v1.1 is configured (RFC 9765 §3.4); the constructor auto-promotes `minimum_tls_version` to `TLSv1_3` in that case.

See [the server docs](server.md#radius11-rfc-9765) for a full description of what changes once v1.1 is negotiated (no MD5, no Message-Authenticator, Token in place of Request Authenticator).
