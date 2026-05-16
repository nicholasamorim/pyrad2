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

::: pyrad2.radsec.server
    handler: python
