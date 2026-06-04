"""Byte-level tests for the shared TLS-EAP framing helpers.

The end-to-end tests in ``test_eap_tls.py`` / ``test_eap_peap.py`` /
``test_eap_ttls.py`` exercise the framing in passing, but a state-
machine bug there manifests as "handshake never completes" — slow to
debug. The targeted tests below let a regression in the byte layout
fail loudly against its own assertion.
"""

from __future__ import annotations

import pytest

from pyrad2.eap._tls_eap import (
    DEFAULT_FRAGMENT_PAYLOAD,
    FLAG_LENGTH,
    FLAG_MORE,
    FLAG_START,
    build_eap_tls_response,
    fragment_outbound,
    join_eap_message_avps,
    parse_eap_tls_request,
    split_into_eap_message_avps,
)


def test_single_fragment_has_no_flags() -> None:
    """Payload below the budget produces one chunk with flags=0."""
    chunks = fragment_outbound(b"\x16\x03\x03\x00\x10" + b"x" * 11)
    assert len(chunks) == 1
    flags, body, total_length = chunks[0]
    assert flags == 0
    assert total_length is None
    assert len(body) == 16


def test_multi_fragment_flag_pattern() -> None:
    """First fragment L|M, middles M-only, last 0."""
    chunks = fragment_outbound(b"\xff" * 800, fragment_size=240)
    assert chunks[0][0] == FLAG_LENGTH | FLAG_MORE
    assert chunks[0][2] == 800
    for flags, _body, _total in chunks[1:-1]:
        assert flags == FLAG_MORE
    assert chunks[-1][0] == 0
    assert chunks[-1][2] is None
    # Reassembly: bodies concatenate back to the original.
    assert b"".join(c[1] for c in chunks) == b"\xff" * 800


def test_default_fragment_size_leaves_room_for_length_header() -> None:
    """240-byte default + 4-byte length header still fits in a single AVP."""
    # 240 + 4 (length) + 5 (EAP header) + 1 (flags) = 250 ≤ 253.
    assert DEFAULT_FRAGMENT_PAYLOAD + 10 <= 253


def test_build_and_parse_roundtrip_single_fragment() -> None:
    """build + parse roundtrip on a non-fragmented payload."""
    payload = b"\x01\x02\x03\x04"
    packet = build_eap_tls_response(eap_id=42, eap_type=13, flags=0, tls_bytes=payload)
    eap_id, eap_type, flags, body = parse_eap_tls_request(packet)
    assert eap_id == 42
    assert eap_type == 13
    assert flags == 0
    assert body == payload


def test_build_and_parse_roundtrip_first_fragment() -> None:
    """First-fragment shape carries L|M and the total-length header."""
    payload = b"\xaa" * 240
    packet = build_eap_tls_response(
        eap_id=7,
        eap_type=25,
        flags=FLAG_LENGTH | FLAG_MORE,
        tls_bytes=payload,
        total_length=800,
    )
    eap_id, eap_type, flags, body = parse_eap_tls_request(packet)
    assert eap_id == 7
    assert eap_type == 25
    assert flags == FLAG_LENGTH | FLAG_MORE
    assert body == payload


def test_build_rejects_l_flag_without_total_length() -> None:
    """L=1 with no total_length is a programmer error, not silent zero."""
    with pytest.raises(ValueError, match="total_length"):
        build_eap_tls_response(eap_id=0, eap_type=13, flags=FLAG_LENGTH, tls_bytes=b"x")


def test_parse_rejects_truncated_header() -> None:
    """A buffer too short to even hold the flags byte must raise."""
    with pytest.raises(ValueError, match="truncated"):
        parse_eap_tls_request(b"\x01\x01\x00\x05")  # missing flags


def test_parse_rejects_truncated_length_header() -> None:
    """L=1 with fewer than 4 bytes after flags must raise."""
    # code, id, length, type, flags=L, then only 2 of the 4 length bytes
    bad = bytes([2, 1, 0, 9, 13, FLAG_LENGTH, 0, 0])
    with pytest.raises(ValueError, match="Length header"):
        parse_eap_tls_request(bad)


def test_eap_message_avp_split_and_join() -> None:
    """RFC 3579 §3.1 split/join round-trips byte-exact for large payloads."""
    big = bytes(range(256)) * 5  # 1280 bytes, much more than one AVP
    avps = split_into_eap_message_avps(big)
    assert all(len(avp) <= 253 for avp in avps)
    assert len(avps) == 6  # 1280 / 253 rounded up
    assert join_eap_message_avps(avps) == big


def test_eap_message_avp_fits_in_one_avp() -> None:
    """Sub-253-byte payload doesn't get unnecessarily split."""
    small = b"\x02\x01\x00\x05\x01"  # bare EAP-Response/Identity
    avps = split_into_eap_message_avps(small)
    assert avps == [small]


def test_start_flag_constant_matches_rfc() -> None:
    """Sanity check: spec-defined bit positions."""
    assert FLAG_LENGTH == 0x80
    assert FLAG_MORE == 0x40
    assert FLAG_START == 0x20
