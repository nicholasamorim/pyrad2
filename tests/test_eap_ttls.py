"""End-to-end EAP-TTLS tests against the in-process TLS server harness.

EAP-TTLS layers a Diameter AVP exchange inside the TLS tunnel rather
than another EAP exchange (PEAP's approach). pyrad2 implements PAP
as the inner method — User-Name and User-Password in cleartext,
protected by the outer TLS. The tests drive a full conversation,
decrypt the inner payload via the harness, and pin both AVP wire
shape and credential values.
"""

from __future__ import annotations

import os

import pytest

from pyrad2.eap import TtlsMethod
from pyrad2.eap._tls_eap import STATE_ATTR
from pyrad2.eap.ttls import (
    AVP_FLAG_MANDATORY,
    AVP_USER_NAME,
    AVP_USER_PASSWORD,
    EAP_TYPE_TTLS,
    decode_diameter_avps,
    encode_diameter_avp,
)

from tests._tls_eap_harness import FakeAuthPacket, TlsEapServer
from tests.base import TEST_ROOT_PATH

CA_CERT = os.path.join(TEST_ROOT_PATH, "certs/ca/ca.cert.pem")
SERVER_CERT = os.path.join(TEST_ROOT_PATH, "certs/server/server.cert.pem")
SERVER_KEY = os.path.join(TEST_ROOT_PATH, "certs/server/server.key.pem")

_MAX_ROUNDS = 80


def _drive_ttls(
    method: TtlsMethod,
    server: TlsEapServer,
    user_name: bytes,
    user_password: bytes,
) -> int:
    """Drive the TTLS exchange to completion, return the round count."""
    pkt = FakeAuthPacket()
    pkt[1] = [user_name]
    pkt[2] = [user_password]
    method.start(pkt)
    challenge = server.start_request()
    for round_no in range(1, _MAX_ROUNDS + 1):
        method.respond(pkt, challenge)
        assert STATE_ATTR in pkt
        next_challenge = server.handle_response(pkt)
        if next_challenge is None:
            return round_no
        challenge = next_challenge
    raise AssertionError(f"EAP-TTLS did not complete within {_MAX_ROUNDS} rounds")


def test_diameter_avp_roundtrip() -> None:
    """encode_diameter_avp + decode_diameter_avps is byte-symmetric."""
    name = encode_diameter_avp(AVP_USER_NAME, b"alice")
    pw = encode_diameter_avp(AVP_USER_PASSWORD, b"hunter2")
    decoded = decode_diameter_avps(name + pw)
    assert len(decoded) == 2
    assert decoded[0] == (AVP_USER_NAME, AVP_FLAG_MANDATORY, None, b"alice")
    assert decoded[1] == (AVP_USER_PASSWORD, AVP_FLAG_MANDATORY, None, b"hunter2")


def test_diameter_avp_4byte_alignment() -> None:
    """Padded AVPs decode back without leaking padding bytes."""
    # 5-byte data — header is 8, body 13, pad to 16.
    encoded = encode_diameter_avp(AVP_USER_NAME, b"alice")
    # 8-byte header + 5-byte data = 13; expect 3-byte zero padding.
    assert len(encoded) == 16
    assert encoded[-3:] == b"\x00\x00\x00"
    decoded = decode_diameter_avps(encoded)
    assert decoded[0][3] == b"alice"  # no padding leak


def test_diameter_avp_rejects_truncated_header() -> None:
    """A buffer shorter than 8 bytes is a malformed AVP."""
    with pytest.raises(ValueError, match="truncated"):
        decode_diameter_avps(b"\x00\x00\x00")


def test_diameter_avp_rejects_overlong_length() -> None:
    """A length field that claims more bytes than the buffer holds is bogus."""
    # Code 1, M flag, length 0xFFFFFF (way more than buffer).
    forged = b"\x00\x00\x00\x01" + b"\x40" + b"\xff\xff\xff"
    with pytest.raises(ValueError, match="overruns"):
        decode_diameter_avps(forged)


def test_ttls_full_exchange_delivers_pap_credentials() -> None:
    """Full TTLS conversation; verify the decrypted inner AVPs.

    The harness captures whatever the supplicant pushed encrypted
    after handshake; we decode it as a Diameter AVP stream and check
    both User-Name and User-Password landed.
    """
    inner_capture: list[bytes] = []
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        eap_type=EAP_TYPE_TTLS,
        require_client_cert=False,
        inner_capture=inner_capture,
        expected_inner_captures=1,
    )
    method = TtlsMethod(
        ca_cert=CA_CERT,
        outer_identity=b"anonymous@example.com",
    )
    _drive_ttls(
        method, server, user_name=b"alice@example.com", user_password=b"hunter2"
    )

    assert server.handshake_done
    assert len(inner_capture) == 1
    avps = decode_diameter_avps(inner_capture[0])
    by_code = {code: data for code, _flags, _vendor, data in avps}
    assert by_code[AVP_USER_NAME] == b"alice@example.com"
    assert by_code[AVP_USER_PASSWORD] == b"hunter2"
    # Both AVPs must carry the Mandatory flag per RFC 5281 §11.2.
    for code, flags, _vendor, _data in avps:
        assert flags & AVP_FLAG_MANDATORY, f"AVP {code} missing M flag"


def test_ttls_requires_user_name_and_password() -> None:
    """Missing User-Name on the outer packet must raise before any wire send."""
    inner_capture: list[bytes] = []
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        eap_type=EAP_TYPE_TTLS,
        require_client_cert=False,
        inner_capture=inner_capture,
        expected_inner_captures=1,
    )
    method = TtlsMethod(ca_cert=CA_CERT)
    pkt = FakeAuthPacket()
    # Only User-Password — no User-Name.
    pkt[2] = [b"pw"]
    method.start(pkt)
    challenge = server.start_request()
    raised = False
    for _ in range(_MAX_ROUNDS):
        try:
            method.respond(pkt, challenge)
        except ValueError as exc:
            assert "User-Name" in str(exc) or "User-Password" in str(exc)
            raised = True
            break
        next_challenge = server.handle_response(pkt)
        if next_challenge is None:
            break
        challenge = next_challenge
    assert raised, "TTLS must raise when User-Name is missing"


def test_ttls_does_not_resend_credentials_on_subsequent_rounds() -> None:
    """The supplicant pushes inner AVPs exactly once, not on every round.

    Servers that hold the TLS connection open after auth (or send
    multiple ACK rounds) must not see the password re-emitted —
    that's both a wire-bandwidth waste and a defensive nicety.
    """
    inner_capture: list[bytes] = []
    server = TlsEapServer(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        eap_type=EAP_TYPE_TTLS,
        require_client_cert=False,
        inner_capture=inner_capture,
        expected_inner_captures=1,
    )
    method = TtlsMethod(ca_cert=CA_CERT)
    _drive_ttls(method, server, user_name=b"alice", user_password=b"hunter2")
    assert len(inner_capture) == 1  # exactly one push, not multiple
