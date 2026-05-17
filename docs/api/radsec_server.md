# RadSec Server

RadSec uses RADIUS over TLS on TCP port 2083. PyRad2's RadSec server uses secure
TLS defaults:

- client certificates are required by default (`ssl.CERT_REQUIRED`)
- TLS 1.2 or newer is required by default
- the server can optionally restrict clients by SHA-256 certificate fingerprint

The examples include a local development CA, server certificate, and client
certificate under `examples/certs`. The bundled server certificate is valid for
`localhost`, `127.0.0.1`, `::1`, and `radsec-server`, so the example client can
run with hostname validation enabled.

These certificates and private keys are for local development only. For real
deployments, generate certificates from your own CA and make sure the server
certificate contains a `subjectAltName` entry for the DNS name or IP address
clients use to connect.

To pin which client certificates may connect, pass one or more SHA-256
certificate fingerprints with `allowed_client_fingerprints`:

```python
server = RadSecServer(
    hosts=hosts,
    dictionary=dictionary,
    certfile="certs/server/server.cert.pem",
    keyfile="certs/server/server.key.pem",
    ca_certfile="certs/ca/ca.cert.pem",
    allowed_client_fingerprints={
        "sha256:12:34:56:...",
    },
)
```

Fingerprints may be plain lowercase/uppercase hex, colon-separated hex, or
prefixed with `sha256:`. PyRad2 normalizes the value before comparing it with
the SHA-256 fingerprint of the presented client certificate. If
`allowed_client_fingerprints` is omitted or empty, any certificate trusted by
`ca_certfile` is accepted.

The server reads packets in a loop on each accepted TLS connection. By default,
the connection stays open until the client disconnects. You can bound long-lived
connections with `connection_read_timeout` and `max_packets_per_connection`:

```python
server = RadSecServer(
    hosts=hosts,
    dictionary=dictionary,
    certfile="certs/server/server.cert.pem",
    keyfile="certs/server/server.key.pem",
    ca_certfile="certs/ca/ca.cert.pem",
    connection_read_timeout=30,
    max_packets_per_connection=1000,
)
```

Use `verify_packet=True` when the server should verify request authenticators
before dispatching to your handlers. Access-Request, Accounting, CoA, and
Disconnect packets are verified with their packet-specific verifier.

RadSec carries all RADIUS packet types on the same TLS/TCP listener. A subclass
must implement `handle_access_request()` and `handle_accounting()`. CoA and
Disconnect handlers are optional because they are Dynamic Authorization Server
behavior; by default PyRad2 responds to unsupported requests with `CoA-NAK` or
`Disconnect-NAK` and `Error-Cause = Unsupported-Extension`.

If a subclass does implement those handlers but you want to disable dispatch,
set `enable_coa=False` or `enable_disconnect=False`:

```python
server = RadSecServer(
    hosts=hosts,
    dictionary=dictionary,
    certfile="certs/server/server.cert.pem",
    keyfile="certs/server/server.key.pem",
    ca_certfile="certs/ca/ca.cert.pem",
    enable_coa=False,
    enable_disconnect=False,
)
```

## Message-Authenticator policy

PyRad2 validates `Message-Authenticator` whenever the attribute is present. By
default, packets containing `EAP-Message` must include a valid
`Message-Authenticator`, while non-EAP packets remain compatible with older
clients.

To require `Message-Authenticator` on every incoming packet, enable
`require_message_authenticator`:

```python
server = RadSecServer(
    hosts=hosts,
    dictionary=dictionary,
    certfile="certs/server/server.cert.pem",
    keyfile="certs/server/server.key.pem",
    ca_certfile="certs/ca/ca.cert.pem",
    require_message_authenticator=True,
)
```

Replies automatically include `Message-Authenticator` when the request included
one, when `require_message_authenticator=True`, or when the reply contains
`EAP-Message`.

RadSec servers answer RFC 5997 Status-Server health checks directly with
`Access-Accept`. Status-Server requests must include a valid
`Message-Authenticator` and do not invoke normal authentication, accounting, or
CoA handlers.

Use `examples/status_radsec.py` to send a Status-Server request to
`examples/server_radsec.py`. The plain `examples/status.py` script uses UDP
RADIUS on port 1812 and will not reach a RadSec server listening on TLS/TCP
port 2083.

::: pyrad2.radsec.server
    handler: python
