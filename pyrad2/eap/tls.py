"""EAP-TLS (RFC 5216) — certificate-based mutual authentication.

EAP-TLS is the strongest of the production EAP methods: both ends
present X.509 certificates and the EAP session reduces to running a
TLS handshake to completion over EAP-Message framing. There is no
password, no shared secret, and no inner method — if the handshake
succeeds, the server returns ``Access-Accept`` and the EAP session is
done.

Conversation shape (RFC 5216 §2.1)::

    1. Client → Server   Access-Request / EAP-Response/Identity
    2. Server → Client   Access-Challenge / EAP-Request/EAP-TLS, S=1
    3. Client → Server   EAP-Response/EAP-TLS, ClientHello
    4. Server → Client   EAP-Request/EAP-TLS, ServerHello..ServerHelloDone
                         (typically fragmented across several rounds)
    5. Client → Server   EAP-Response/EAP-TLS, Certificate, ClientKeyExchange,
                         CertificateVerify, ChangeCipherSpec, Finished
    6. Server → Client   EAP-Request/EAP-TLS, ChangeCipherSpec, Finished
    7. Client → Server   EAP-Response/EAP-TLS, *empty* (RFC 5216 §2.1.5)
    8. Server → Client   Access-Accept (+ MS-MPPE-Send/Recv-Key)

The shared template in :mod:`pyrad2.eap._tls_eap` owns steps 3 / 5 /
7's framing, fragmentation, and the engine state machine; this module
only sets the ``EAP_TYPE`` constant and inherits the default
no-op inner hook because EAP-TLS has no post-handshake exchange.

MSK derivation — turning the TLS master secret into the MS-MPPE-Send
/ Recv keys the server packs into the final Access-Accept — is the
**server's** responsibility, not the supplicant's. pyrad2's role here
is the supplicant; we drive the handshake and read the resulting
Accept, no key export needed.
"""

from __future__ import annotations

from pyrad2.eap._tls_eap import TlsEapMethodBase

# RFC 5216 §3.1 — EAP-TLS uses EAP-Type 13.
EAP_TYPE_TLS = 13


class TlsMethod(TlsEapMethodBase):
    """EAP-TLS supplicant driver.

    A fresh ``TlsMethod`` is created per conversation by the registry;
    the per-conversation TLS engine, fragmentation buffer, and
    outbound queue live on the instance. The instance is **bound** to
    a single ``SSLContext`` — typically built via
    :func:`pyrad2.eap._tls_eap.make_client_tls_context`. Tests
    substitute their own context to thread a generated CA into the
    trust store.

    The pattern is::

        from pyrad2.eap.tls import TlsMethod
        from pyrad2.eap import register_method

        register_method(
            "eap-tls",
            lambda: TlsMethod(
                ca_cert="/etc/pki/aaa-ca.pem",
                client_cert="/etc/pki/client.crt",
                client_key="/etc/pki/client.key",
            ),
        )

    Both ``ca_cert`` and the client cert/key pair are constructor
    args; this method has no use for ``User-Password`` so callers
    don't need to populate one on the outgoing packet. Unlike PEAP /
    TTLS, the default outer identity falls back to the packet's
    ``User-Name`` rather than to ``b"anonymous"`` — EAP-TLS's
    confidentiality story is the certificate, not the outer
    identity.
    """

    EAP_TYPE = EAP_TYPE_TLS
