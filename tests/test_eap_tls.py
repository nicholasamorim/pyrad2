"""End-to-end EAP-TLS tests against an in-process TLS server harness.

The harness in ``tests/_tls_eap_harness.py`` exposes the server side
of an EAP-TLS handshake driven through ``ssl.MemoryBIO``. The tests
here drive a full conversation between pyrad2's :class:`TlsMethod`
supplicant and that harness, asserting:

* the EAP-Response/Identity comes out shaped correctly,
* the TLS handshake completes in a bounded number of rounds, and
* both endpoints agree on the same negotiated TLS protocol version.

Framing-level unit tests for ``_tls_eap`` live separately in
``test_eap_tls_framing.py`` so a regression in the byte packing
fails its own targeted test rather than only manifesting as a
mid-handshake stall here.
"""

from __future__ import annotations

import os
import ssl

import pytest

from pyrad2.eap._tls_eap import EAP_MESSAGE_ATTR, STATE_ATTR
from pyrad2.eap.tls import EAP_TYPE_TLS, TlsMethod

from tests._tls_eap_harness import FakeAuthPacket, TlsEapServer
from tests.base import TEST_ROOT_PATH

# Reuse the cert tree the RadSec tests already built. EAP-TLS needs a
# mutual-trust setup: the client trusts the CA the server's cert was
# issued under, and the server trusts the CA the client's cert was
# issued under. Both ends here share the same CA in tests/certs/ca.
CA_CERT = os.path.join(TEST_ROOT_PATH, "certs/ca/ca.cert.pem")
SERVER_CERT = os.path.join(TEST_ROOT_PATH, "certs/server/server.cert.pem")
SERVER_KEY = os.path.join(TEST_ROOT_PATH, "certs/server/server.key.pem")
CLIENT_CERT = os.path.join(TEST_ROOT_PATH, "certs/client/client.cert.pem")
CLIENT_KEY = os.path.join(TEST_ROOT_PATH, "certs/client/client.key.pem")


# Hard ceiling on the number of EAP rounds we'll drive before giving
# up. The server's certificate flight is the dominant cost — a 1.2KB
# cert plus the chain plus ServerKeyExchange easily spans 10+ EAP
# fragments at our 240-byte payload budget, and the client's
# Certificate + ClientKeyExchange + Finished spans another handful.
# 60 leaves comfortable headroom; anything above is a state-machine
# bug, not slow crypto.
_MAX_ROUNDS = 60


def _build_client_method() -> TlsMethod:
    """Build a TlsMethod configured against the bundled test certs."""
    return TlsMethod(
        ca_cert=CA_CERT,
        client_cert=CLIENT_CERT,
        client_key=CLIENT_KEY,
        identity=b"alice",
    )


def _drive_handshake(method: TlsMethod, server: TlsEapServer) -> int:
    """Run the EAP exchange to completion, return the round count.

    Pattern matches the production client loop in
    ``pyrad2.client._send_auth_packet`` but inlined so the test asserts
    on the same packets the production code would see.
    """
    pkt = FakeAuthPacket()
    method.start(pkt)
    assert EAP_MESSAGE_ATTR in pkt, "start() must seed EAP-Message"

    # First server response is the Start request (S=1).
    challenge = server.start_request()

    for round_no in range(1, _MAX_ROUNDS + 1):
        method.respond(pkt, challenge)
        # State must always carry across an EAP round.
        assert STATE_ATTR in pkt, f"round {round_no}: respond() dropped State"
        next_challenge = server.handle_response(pkt)
        if next_challenge is None:
            return round_no
        challenge = next_challenge
    raise AssertionError(
        f"EAP-TLS handshake did not complete within {_MAX_ROUNDS} rounds"
    )


def test_eap_tls_handshake_completes() -> None:
    """Full EAP-TLS handshake against the in-process harness."""
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        ca_cert=CA_CERT,
        eap_type=EAP_TYPE_TLS,
        require_client_cert=True,
    )
    method = _build_client_method()
    rounds = _drive_handshake(method, server)
    assert server.handshake_done, "TLS handshake never completed on the server side"
    assert method._engine.handshake_done, "client engine never marked handshake_done"
    assert rounds <= _MAX_ROUNDS


def test_eap_tls_negotiates_at_least_tls_1_2() -> None:
    """Negotiated protocol must respect the RFC 9325 floor."""
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        ca_cert=CA_CERT,
        eap_type=EAP_TYPE_TLS,
        require_client_cert=True,
    )
    method = _build_client_method()
    _drive_handshake(method, server)
    # SSLObject exposes the negotiated version once the handshake is
    # complete on both sides. We assert the floor rather than pinning a
    # specific version — the OpenSSL/Python build will pick the
    # strongest mutually supported.
    version = server._sslobj.version()
    assert version is not None and version.startswith(("TLSv1.2", "TLSv1.3"))


def test_eap_tls_method_seeds_identity_response() -> None:
    """start() seeds an EAP-Response/Identity carrying the bound identity."""
    method = TlsMethod(
        ca_cert=CA_CERT,
        client_cert=CLIENT_CERT,
        client_key=CLIENT_KEY,
        identity=b"alice@example.com",
    )
    pkt = FakeAuthPacket()
    method.start(pkt)
    avps = pkt[EAP_MESSAGE_ATTR]
    assert len(avps) == 1, "Identity response fits in one AVP"
    payload = avps[0]
    # EAP-Response (2), some id, length, EAP-Type=Identity (1), identity bytes
    assert payload[0] == 2
    assert payload[4] == 1
    assert payload[5:] == b"alice@example.com"


def test_eap_tls_rejects_wrong_inner_eap_type() -> None:
    """Server sending EAP-Type != 13 mid-conversation is a hard error."""
    method = _build_client_method()
    pkt = FakeAuthPacket()
    method.start(pkt)
    # Forge a bogus challenge: EAP-Request, id=1, len=6, type=4 (MD5)
    # — which would be valid EAP but isn't EAP-TLS. The method must
    # raise so the supplicant can fail loud rather than silently
    # dropping the conversation.
    forged = FakeAuthPacket()
    forged[EAP_MESSAGE_ATTR] = [bytes([1, 1, 0, 6, 4, 0])]
    forged[STATE_ATTR] = [b"\x00"]
    with pytest.raises(ValueError, match="Expected EAP-Type 13"):
        method.respond(pkt, forged)


def test_eap_tls_requires_ca_for_server_validation() -> None:
    """Building a context without a CA falls back to the system trust store.

    A handshake against our locally-issued cert must therefore fail
    when no CA is supplied, because the system store doesn't trust
    our test CA. This protects the "no insecure skip-verify" rule
    baked into ``make_client_tls_context``.
    """
    method = TlsMethod(
        ca_cert=None,
        client_cert=CLIENT_CERT,
        client_key=CLIENT_KEY,
        identity=b"alice",
    )
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        ca_cert=CA_CERT,
        eap_type=EAP_TYPE_TLS,
        require_client_cert=True,
    )
    # The handshake should fail with an SSL error — the server's cert
    # chain doesn't validate against the system trust anchors.
    with pytest.raises(ssl.SSLError):
        _drive_handshake(method, server)
