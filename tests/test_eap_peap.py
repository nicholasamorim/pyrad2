"""End-to-end PEAPv0 tests against the in-process TLS server harness.

PEAP layers a second EAP exchange inside the TLS tunnel that the
outer EAP-TLS-shaped framing built around. The tests here drive:

* the TLS handshake (server-only cert auth — PEAP relaxes mTLS),
* the inner Identity round (server asks, client returns User-Name),
* an inner EAP-MD5 challenge (the simplest stateful inner method to
  exercise the delegate-to-registered-method code path),
* the PEAPv0 Result-TLV success indication, and
* the supplicant's TLV echo back.

The harness's ``inner_script`` parameter takes the sequence of inner
EAP-Request bytes the server will write through the TLS tunnel
post-handshake; ``inner_capture`` collects what the supplicant sent
back so the assertions can pin the exact bytes.
"""

from __future__ import annotations

import hashlib
import os
import struct

from pyrad2.constants import EAPPacketType, EAPType
from pyrad2.eap import (
    PeapMethod,
    register_method,
    registered_methods,
)
from pyrad2.eap._tls_eap import EAP_MESSAGE_ATTR, STATE_ATTR
from pyrad2.eap.peap import (
    EAP_TYPE_PEAP,
    PEAP_TLV_RESULT,
    PEAP_TLV_STATUS_SUCCESS,
    PEAP_TLV_TYPE,
)

from tests._tls_eap_harness import FakeAuthPacket, TlsEapServer
from tests.base import TEST_ROOT_PATH

CA_CERT = os.path.join(TEST_ROOT_PATH, "certs/ca/ca.cert.pem")
SERVER_CERT = os.path.join(TEST_ROOT_PATH, "certs/server/server.cert.pem")
SERVER_KEY = os.path.join(TEST_ROOT_PATH, "certs/server/server.key.pem")

_MAX_ROUNDS = 80  # bigger than EAP-TLS because of the inner round-trip(s)

# EAP-MD5 type code (RFC 3748 §5.4).
EAP_TYPE_MD5 = 4


def _build_eap_request_identity(eap_id: int) -> bytes:
    """Inner EAP-Request/Identity that the harness writes through TLS."""
    return struct.pack("!BBHB", EAPPacketType.REQUEST, eap_id, 5, EAPType.IDENTITY)


def _build_eap_request_md5_challenge(eap_id: int, challenge: bytes) -> bytes:
    """Inner EAP-Request/MD5-Challenge with a fixed 16-byte challenge.

    Per RFC 3748 §5.4: type(4) + value_size(1) + challenge(N) + optional name.
    """
    value_size = len(challenge)
    return (
        struct.pack(
            "!BBHBB",
            EAPPacketType.REQUEST,
            eap_id,
            5 + 1 + value_size,
            EAP_TYPE_MD5,
            value_size,
        )
        + challenge
    )


def _build_peap_tlv_result_request(eap_id: int, status: int) -> bytes:
    """Inner EAP-Request carrying a PEAPv0 Result-TLV."""
    return struct.pack(
        "!BBHB HH H",
        EAPPacketType.REQUEST,
        eap_id,
        11,
        PEAP_TLV_TYPE,
        PEAP_TLV_RESULT,
        2,
        status,
    )


def _drive_peap(
    method: PeapMethod, server: TlsEapServer, user_name: bytes, user_password: bytes
) -> tuple[FakeAuthPacket, int]:
    """Run the PEAP exchange to completion, return final pkt + round count."""
    pkt = FakeAuthPacket()
    pkt[1] = [user_name]
    pkt[2] = [user_password]
    method.start(pkt)
    assert EAP_MESSAGE_ATTR in pkt
    challenge = server.start_request()
    for round_no in range(1, _MAX_ROUNDS + 1):
        method.respond(pkt, challenge)
        assert STATE_ATTR in pkt
        next_challenge = server.handle_response(pkt)
        if next_challenge is None:
            return pkt, round_no
        challenge = next_challenge
    raise AssertionError(f"PEAP exchange did not complete within {_MAX_ROUNDS} rounds")


def test_peap_handshake_only_completes() -> None:
    """Server-only-cert handshake with no inner script still completes.

    PEAP allows server-only TLS auth (mTLS would defeat the point of
    having an inner password method), so the handshake must work with
    no client cert configured.
    """
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        eap_type=EAP_TYPE_PEAP,
        require_client_cert=False,
    )
    method = PeapMethod(
        ca_cert=CA_CERT,
        outer_identity=b"anonymous",
    )
    pkt = FakeAuthPacket()
    method.start(pkt)
    challenge = server.start_request()
    for _ in range(_MAX_ROUNDS):
        method.respond(pkt, challenge)
        next_challenge = server.handle_response(pkt)
        if next_challenge is None:
            break
        challenge = next_challenge
    assert server.handshake_done
    assert method._engine.handshake_done


def test_peap_inner_identity_then_tlv_success() -> None:
    """Full PEAP flow: TLS → inner Identity → Result-TLV success → echo."""
    inner_capture: list[bytes] = []
    inner_script = [
        # First message after handshake: inner EAP-Request/Identity.
        _build_eap_request_identity(eap_id=10),
        # After client returns inner Identity, server jumps straight
        # to a Result-TLV success — degenerate but tests that the
        # PEAP method handles the TLV path even without an inner
        # auth method exchange.
        _build_peap_tlv_result_request(eap_id=11, status=PEAP_TLV_STATUS_SUCCESS),
    ]
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        eap_type=EAP_TYPE_PEAP,
        require_client_cert=False,
        inner_script=inner_script,
        inner_capture=inner_capture,
    )
    method = PeapMethod(
        ca_cert=CA_CERT,
        outer_identity=b"anonymous@realm",
    )
    _drive_peap(method, server, user_name=b"alice", user_password=b"hunter2")

    assert server.handshake_done
    # First inner response must be EAP-Response/Identity carrying the
    # real User-Name from the outer packet.
    assert len(inner_capture) >= 2
    identity_resp = inner_capture[0]
    assert identity_resp[0] == EAPPacketType.RESPONSE
    assert identity_resp[4] == EAPType.IDENTITY
    assert identity_resp[5:] == b"alice"
    # Second inner response must be the TLV echo.
    tlv_resp = inner_capture[1]
    assert tlv_resp[0] == EAPPacketType.RESPONSE
    assert tlv_resp[4] == PEAP_TLV_TYPE
    # Status code 1 (Success) at bytes [9:11].
    assert struct.unpack("!H", tlv_resp[9:11])[0] == PEAP_TLV_STATUS_SUCCESS


def test_peap_inner_md5_method_delegation() -> None:
    """The inner method registry path drives EAP-MD5 inside the tunnel.

    EAP-MD5 is registered out of the box, so naming it as PEAP's
    inner method exercises the full registry-lookup + delegate-to-
    inner-EapMethod path without requiring crypto extras.
    """
    md5_challenge = bytes(range(16))  # arbitrary 16-byte challenge
    inner_capture: list[bytes] = []
    inner_script = [
        _build_eap_request_identity(eap_id=20),
        _build_eap_request_md5_challenge(eap_id=21, challenge=md5_challenge),
        _build_peap_tlv_result_request(eap_id=22, status=PEAP_TLV_STATUS_SUCCESS),
    ]
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        eap_type=EAP_TYPE_PEAP,
        require_client_cert=False,
        inner_script=inner_script,
        inner_capture=inner_capture,
    )
    method = PeapMethod(
        ca_cert=CA_CERT,
        outer_identity=b"anonymous",
        inner_method="eap-md5",
    )
    _drive_peap(method, server, user_name=b"bob", user_password=b"correct horse")

    assert server.handshake_done
    # Capture order: Identity response, MD5 challenge response, TLV echo.
    assert len(inner_capture) == 3
    md5_response = inner_capture[1]
    # EAP-Response, MD5 type, value-size 16, then 16-byte digest.
    assert md5_response[0] == EAPPacketType.RESPONSE
    assert md5_response[4] == EAP_TYPE_MD5
    assert md5_response[5] == 16
    digest = md5_response[6:22]
    # Reproduce the digest with the same inputs to verify the inner
    # method actually ran (vs. being bypassed by PEAP's TLV path).
    expected = hashlib.md5(
        bytes([md5_response[1]]) + b"correct horse" + md5_challenge
    ).digest()
    assert digest == expected


def test_peap_rejects_inner_request_without_configured_method() -> None:
    """An inner non-Identity, non-TLV request with no inner_method raises.

    Defends the credential-handling code path: if the server sends
    inner EAP-Request/MSCHAPv2 but the caller forgot to wire an
    inner method, we must raise loud rather than fall through to a
    degenerate response.
    """
    md5_challenge = bytes(range(16))
    inner_script = [
        _build_eap_request_identity(eap_id=30),
        _build_eap_request_md5_challenge(eap_id=31, challenge=md5_challenge),
    ]
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        eap_type=EAP_TYPE_PEAP,
        require_client_cert=False,
        inner_script=inner_script,
    )
    method = PeapMethod(ca_cert=CA_CERT)  # no inner method!
    pkt = FakeAuthPacket()
    pkt[1] = [b"carol"]
    pkt[2] = [b"pw"]
    method.start(pkt)
    challenge = server.start_request()
    raised = False
    for _ in range(_MAX_ROUNDS):
        try:
            method.respond(pkt, challenge)
        except ValueError as exc:
            assert "inner_method" in str(exc) or "is not registered" in str(exc)
            raised = True
            break
        next_challenge = server.handle_response(pkt)
        if next_challenge is None:
            break
        challenge = next_challenge
    assert raised, "PEAP must raise when an inner method is required but not configured"


def test_peap_registry_round_trip() -> None:
    """``register_method('eap-peap', factory)`` makes it discoverable.

    PEAP isn't auto-registered (the factory needs cert paths), so the
    application is expected to register it. This test pins the
    registration shape callers will use.
    """
    register_method(
        "eap-peap",
        lambda: PeapMethod(ca_cert=CA_CERT, inner_method="eap-md5"),
    )
    assert "eap-peap" in registered_methods()
