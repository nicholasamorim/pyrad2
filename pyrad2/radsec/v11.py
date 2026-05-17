"""RFC 9765 RADIUS/1.1 protocol-version negotiation helpers.

RADIUS/1.1 is selected via TLS ALPN ("radius/1.1" vs "radius/1.0") on the
same RadSec port. The wire layout of the 20-byte header is unchanged at
byte level — only field *semantics* change:

  classic    →   RADIUS/1.1
  Code (1)   →   Code (1)
  Id (1)     →   Reserved-1 (1)  — MUST be 0 when sending, MUST be ignored on receipt
  Length (2) →   Length (2)
  Authenticator (16) → Token (4) + Reserved-2 (12)

The Token is a per-connection 32-bit counter, initialized randomly and
incremented for each unique packet. Retransmissions reuse the Token.

This module is intentionally tiny — it only owns the version enum, ALPN
helpers, and the per-connection Token counter. Conditional behavior
(skipping MD5, etc.) lives in ``pyrad2.packet`` gated on
``Packet.radius_version``. ``pyrad2.dedup`` reads the dedup key from
``Packet.token`` when present (v1.1) and falls back to
``Packet.authenticator`` otherwise (v1.0).
"""

from __future__ import annotations

import secrets
import ssl
from enum import IntEnum
from typing import Sequence

ALPN_V1_0: str = "radius/1.0"
ALPN_V1_1: str = "radius/1.1"


class RadiusVersion(IntEnum):
    """RADIUS protocol version negotiated over the RadSec TLS connection."""

    V1_0 = 0  # historic RADIUS (RFC 2865), MD5-based.
    V1_1 = 1  # RFC 9765, MD5 removed since TLS already authenticates.


_ALPN_BY_VERSION: dict[RadiusVersion, str] = {
    RadiusVersion.V1_0: ALPN_V1_0,
    RadiusVersion.V1_1: ALPN_V1_1,
}

_VERSION_BY_ALPN: dict[str, RadiusVersion] = {
    ALPN_V1_0: RadiusVersion.V1_0,
    ALPN_V1_1: RadiusVersion.V1_1,
}


def version_from_alpn(selected: str | None) -> RadiusVersion:
    """Map ``selected_alpn_protocol()`` output to a ``RadiusVersion``.

    ``None`` (peer didn't negotiate ALPN at all, or didn't offer any
    radius/* protocol) defaults to ``V1_0`` so the historic RadSec
    behavior is preserved when only one side is upgraded.

    Prefer ``negotiate()`` for endpoint code — that function honors the
    operator's configured-version set and signals strict-mode mismatches
    explicitly, per RFC 9765 §3.3.
    """
    if selected is None:
        return RadiusVersion.V1_0
    return _VERSION_BY_ALPN.get(selected, RadiusVersion.V1_0)


class NoCommonRadiusVersion(Exception):
    """Raised when ALPN negotiation produced no shared RADIUS version.

    RFC 9765 §3.3 mandates that a strict-mode endpoint (one that did not
    advertise ``radius/1.0``) MUST close the connection when the peer
    didn't pick a supported protocol. The TLS layer enforces this when
    the peer offered any ALPN names that didn't match (alert 120); this
    exception covers the case where the peer offered no ALPN at all and
    the local side requires v1.1.
    """


def negotiate(
    configured: Sequence[RadiusVersion], selected_alpn: str | None
) -> RadiusVersion:
    """Resolve the ALPN handshake outcome to a usable ``RadiusVersion``.

    The TLS stack already rejects "peer offered ALPN but no overlap"
    with alert 120 before we ever see the connection. The remaining
    case is "peer didn't offer ALPN" — for which:

    - If we advertise ``V1_0`` (any config that includes it), fall back
      to v1.0 for backward compatibility with historic peers.
    - If we're strict v1.1-only, raise ``NoCommonRadiusVersion``; the
      caller MUST close the connection (RFC 9765 §3.3).
    """
    if selected_alpn is not None:
        chosen = _VERSION_BY_ALPN.get(selected_alpn)
        if chosen is None or chosen not in configured:
            # Shouldn't happen — the TLS stack would have rejected — but
            # be defensive: never trust a version we didn't advertise.
            raise NoCommonRadiusVersion(
                f"peer selected unsupported ALPN {selected_alpn!r}"
            )
        return chosen
    if RadiusVersion.V1_0 in configured:
        return RadiusVersion.V1_0
    raise NoCommonRadiusVersion(
        "peer did not offer ALPN; local endpoint requires RADIUS/1.1"
    )


def enforce_tls_version_floor(
    minimum: ssl.TLSVersion, versions: Sequence[RadiusVersion]
) -> ssl.TLSVersion:
    """Return a TLS minimum that satisfies RFC 9765 §3.4.

    RADIUS/1.1 mandates *"Implementations of this specification MUST
    require TLS version 1.3 or later."* If ``V1_1`` is in ``versions``,
    auto-promote the floor to TLS 1.3 when the caller asked for less.
    A caller that explicitly pins a higher minimum keeps their value.
    """
    if RadiusVersion.V1_1 not in versions:
        return minimum
    if minimum < ssl.TLSVersion.TLSv1_3:
        return ssl.TLSVersion.TLSv1_3
    return minimum


def apply_alpn(ctx: ssl.SSLContext, versions: Sequence[RadiusVersion]) -> None:
    """Advertise RADIUS protocol versions via ALPN on ``ctx``.

    Skipped entirely when ``versions == (V1_0,)`` so existing RadSec
    deployments see byte-identical TLS hellos and aren't affected by the
    feature being available.

    The wire order is always **highest version first** regardless of the
    order the caller passed in: OpenSSL's server-side ALPN callback picks
    the first protocol in the server's list that the client also offered,
    so leading with ``radius/1.1`` makes v1.1 the preferred outcome when
    both sides advertise both versions (RFC 9765 §3.3 SHOULD).
    """
    if not versions:
        raise ValueError("versions must contain at least one RadiusVersion")
    if tuple(versions) == (RadiusVersion.V1_0,):
        return
    ordered = sorted(set(versions), reverse=True)
    ctx.set_alpn_protocols([_ALPN_BY_VERSION[v] for v in ordered])


class TokenCounter:
    """Per-connection 32-bit Token counter (RFC 9765 §4.1).

    Initialized to a random value to make replay across connection
    restarts unlikely and incremented per outgoing packet. The 4-byte
    big-endian encoding lives in the first four bytes of the packet's
    Authenticator field; the remaining twelve bytes are Reserved-2.
    """

    _MASK = 0xFFFFFFFF

    def __init__(self) -> None:
        self._value = secrets.randbits(32)

    def next(self) -> bytes:
        """Return the next 4-byte big-endian Token and advance the counter."""
        token = self._value.to_bytes(4, "big")
        self._value = (self._value + 1) & self._MASK
        return token
