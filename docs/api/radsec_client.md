# RadSec Client

RadSec is a TCP/TLS stream transport. `RadSecClient` reuses its TLS connection
by default so multiple `send_packet()` calls can share the same connection. This
is the recommended mode for normal RadSec use.

Use `reuse_connection=False` only as a legacy/compatibility escape hatch when a
deployment specifically needs one TLS connection per packet, such as for
interoperability debugging, short-lived scripts, or a peer that cannot handle
multiple RADIUS packets on one TLS stream:

```python
client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=dictionary,
    certfile="certs/client/client.cert.pem",
    keyfile="certs/client/client.key.pem",
    certfile_server="certs/ca/ca.cert.pem",
    reuse_connection=False,
)
```

The existing `timeout` value is used for connection establishment, writing, and
waiting for each response packet. If a reusable connection fails, the client
closes it, waits `reconnect_backoff` seconds, and retries up to `retries` times:

```python
client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=dictionary,
    certfile="certs/client/client.cert.pem",
    keyfile="certs/client/client.key.pem",
    certfile_server="certs/ca/ca.cert.pem",
    retries=3,
    timeout=5,
    reconnect_backoff=0.25,
)
```

When you are done with a reusable client, close it explicitly or use it as an
async context manager:

```python
async with RadSecClient(...) as client:
    reply = await client.send_packet(request)
```

`RadSecClient` automatically adds `Message-Authenticator` to outgoing
`Access-Request` packets that contain `EAP-Message`.

Use `create_status_packet()` for RFC 5997 Status-Server health checks. The
request automatically includes the mandatory `Message-Authenticator`:

```python
request = client.create_status_packet()
reply = await client.send_packet(request)
```

The UDP Status-Server example (`examples/status.py`) talks to a normal RADIUS
server on UDP/1812. To check a RadSec server such as
`examples/server_radsec.py`, use the TLS/TCP example instead:

```shell
PYTHONPATH=. uv run examples/status_radsec.py
```

::: pyrad2.radsec.client
    handler: python
