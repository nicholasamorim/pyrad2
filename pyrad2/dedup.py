"""RFC 5080 §2.2.2 duplicate detection and response cache.

A RADIUS server MUST detect duplicate requests and resend the original
response without re-running the handler. The duplicate key is
``(src IP, src UDP port, code, Identifier, Request Authenticator)``.

The cache here is in-memory only (RFC 5080 permits dropping state on
restart). Entries are evicted on TTL expiry or when the LRU cap is hit.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Optional

from pyrad2.constants import PacketType

# Codes for which RFC 5080 dedup applies. Replies (Access-Accept etc.) and
# Status-Server packets are explicitly excluded.
_DEDUPABLE_CODES: frozenset[int] = frozenset(
    {
        PacketType.AccessRequest,
        PacketType.AccountingRequest,
        PacketType.CoARequest,
        PacketType.DisconnectRequest,
    }
)


@dataclass(frozen=True, slots=True)
class DedupKey:
    """RFC 5080 §2.2.2 duplicate-detection tuple."""

    src_ip: Any
    src_port: Any
    code: int
    identifier: int
    request_authenticator: bytes


# Sentinel returned by ``ResponseCache.lookup`` when the original request
# is still being processed by the handler.
class _InFlight:
    __slots__ = ()

    def __repr__(self) -> str:
        return "IN_FLIGHT"


IN_FLIGHT = _InFlight()


# Sentinel returned by ``ResponseCache.lookup`` when the original request
# completed without producing a reply (handler raised or returned
# silently). Retransmissions within the TTL window are suppressed so the
# handler doesn't re-run — RFC 5080 §2.2.2 expects the server to drop the
# retry regardless of whether the original attempt produced bytes on the
# wire. Distinct from ``IN_FLIGHT`` so future debugging can tell "original
# is still running" apart from "original gave up".
class _DropNoReply:
    __slots__ = ()

    def __repr__(self) -> str:
        return "DROP_NOREPLY"


DROP_NOREPLY = _DropNoReply()


class DispatchAction(IntEnum):
    """Outcome of consulting the response cache for an incoming request."""

    PROCESS = 0  # No cache hit. Caller should run the handler.
    DROP = 1  # Duplicate of an in-flight or dropped request. Drop silently.
    RESENT = 2  # Cached reply was found and replayed by ``consult_cache``.


def key_for(pkt: Any, source: Any = None) -> Optional[DedupKey]:
    """Build the RFC 5080 dedup key for ``pkt`` or return ``None``.

    ``source`` defaults to ``pkt.source``; pass it explicitly for the
    async server which keeps the address alongside the packet rather
    than on it.

    Returns ``None`` for packet shapes that don't carry the fields we need
    (e.g. unit-test stand-ins) or for codes the spec excludes from dedup.
    """
    code = getattr(pkt, "code", None)
    if code is None or int(code) not in _DEDUPABLE_CODES:
        return None
    src = source if source is not None else getattr(pkt, "source", None)
    if not src or len(src) < 2:
        return None
    # RFC 9765 §4.1: in RADIUS/1.1 the Request Authenticator is replaced
    # by a 4-byte Token. Dedup keys on whichever field carries the
    # client-chosen correlator: token first (v1.1), authenticator
    # otherwise (v1.0).
    correlator = getattr(pkt, "token", None) or getattr(pkt, "authenticator", None)
    if not correlator:
        return None
    ident = getattr(pkt, "id", None)
    if ident is None:
        return None
    return DedupKey(src[0], src[1], int(code), int(ident), bytes(correlator))


class ResponseCache:
    """LRU+TTL cache of reply bytes keyed by ``DedupKey``.

    Thread-safe so it can be shared between the sync server's main loop
    and any worker threads a subclass may use. The async server reuses
    the same class without contention.
    """

    def __init__(
        self,
        ttl: float = 30.0,
        max_entries: int = 4096,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.ttl = ttl
        self.max_entries = max_entries
        self._clock = clock
        self._lock = threading.RLock()
        self._in_flight: set[DedupKey] = set()
        # OrderedDict ordered by recency of insert/refresh — newest at end.
        self._cached: "OrderedDict[DedupKey, tuple[bytes, float]]" = OrderedDict()
        # Keys whose handler completed without producing a reply (raised
        # or returned silently). Retransmissions within the entry's TTL
        # are dropped so the handler doesn't re-run.
        self._dropped: "OrderedDict[DedupKey, float]" = OrderedDict()

    def lookup(self, key: DedupKey):
        """Return the cache verdict for ``key``.

        One of:

        - ``bytes`` — a cached reply; replay it on the wire.
        - ``IN_FLIGHT`` — the original handler is still running; drop.
        - ``DROP_NOREPLY`` — the original handler completed without
          producing a reply; drop (RFC 5080 §2.2.2).
        - ``None`` — no entry; the caller should run the handler.
        """
        now = self._clock()
        with self._lock:
            entry = self._cached.get(key)
            if entry is not None:
                raw, expires_at = entry
                if now < expires_at:
                    self._cached.move_to_end(key)
                    return raw
                del self._cached[key]
            drop_expires_at = self._dropped.get(key)
            if drop_expires_at is not None:
                if now < drop_expires_at:
                    self._dropped.move_to_end(key)
                    return DROP_NOREPLY
                del self._dropped[key]
            if key in self._in_flight:
                return IN_FLIGHT
            return None

    def mark_in_flight(self, key: DedupKey) -> None:
        with self._lock:
            self._in_flight.add(key)

    def drop_in_flight(self, key: DedupKey) -> None:
        """Remove the in-flight marker without recording a DROP sentinel.

        Kept for backwards compatibility; ``mark_dropped_if_in_flight``
        is preferred for the post-3.0 dispatch path because it honours
        RFC 5080's "drop retransmissions of failed handlers" rule.
        """
        with self._lock:
            self._in_flight.discard(key)

    def mark_dropped_if_in_flight(
        self, key: DedupKey, ttl: Optional[float] = None
    ) -> None:
        """Transition ``key`` from in-flight to dropped.

        Idempotent: if ``key`` isn't in flight (e.g. ``record_reply``
        already moved it to ``_cached``) this is a no-op. That makes
        it safe to call unconditionally from a ``finally`` clause —
        a successful handler that sent a reply ends up cached; an
        exception or silent return ends up dropped.
        """
        expires_at = self._clock() + (self.ttl if ttl is None else ttl)
        with self._lock:
            if key not in self._in_flight:
                return
            self._in_flight.discard(key)
            self._dropped[key] = expires_at
            self._dropped.move_to_end(key)
            self._evict_locked()

    def record_reply(
        self, key: DedupKey, raw: bytes, ttl: Optional[float] = None
    ) -> None:
        """Atomically transition the entry from in-flight to cached."""
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError("raw must be bytes")
        expires_at = self._clock() + (self.ttl if ttl is None else ttl)
        with self._lock:
            self._in_flight.discard(key)
            # A previous failed attempt might have left a DROP sentinel
            # for this key; the successful reply supersedes it.
            self._dropped.pop(key, None)
            self._cached[key] = (bytes(raw), expires_at)
            self._cached.move_to_end(key)
            self._evict_locked()

    def clear(self) -> None:
        with self._lock:
            self._cached.clear()
            self._in_flight.clear()
            self._dropped.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cached)

    def _evict_locked(self) -> None:
        now = self._clock()
        # Drop expired entries from the front (oldest).
        while self._cached:
            key, (_, expires_at) = next(iter(self._cached.items()))
            if expires_at > now:
                break
            del self._cached[key]
        # Same for the drop sentinel store.
        while self._dropped:
            key, expires_at = next(iter(self._dropped.items()))
            if expires_at > now:
                break
            del self._dropped[key]
        # Enforce the LRU cap on cached entries (drop sentinels are
        # bounded by TTL alone — they don't carry payload bytes).
        while len(self._cached) > self.max_entries:
            self._cached.popitem(last=False)


def consult_cache(
    cache: Optional[ResponseCache],
    key: Optional[DedupKey],
    resend: Callable[[bytes], None],
) -> DispatchAction:
    """Single point of policy for the dedup state machine.

    Returns one of:

    - ``PROCESS`` if the caller should run the handler. The key is marked
      in-flight before returning, so retries that arrive while the
      handler is still running are dropped.
    - ``DROP`` if the original is in-flight OR was marked as no-reply
      because the previous handler raised/dropped (RFC 5080 §2.2.2).
    - ``RESENT`` if a cached reply was found; ``resend(raw_bytes)`` has
      already been invoked.
    """
    if cache is None or key is None:
        return DispatchAction.PROCESS
    entry = cache.lookup(key)
    if entry is IN_FLIGHT or entry is DROP_NOREPLY:
        return DispatchAction.DROP
    if entry is not None:
        resend(entry)  # type: ignore[arg-type]
        return DispatchAction.RESENT
    cache.mark_in_flight(key)
    return DispatchAction.PROCESS


def record_if_keyed(cache: Optional[ResponseCache], reply: Any, raw: bytes) -> None:
    """Cache ``raw`` if the reply carries a dedup key from its request."""
    key = getattr(reply, "_dedup_key", None)
    if key is not None and cache is not None:
        cache.record_reply(key, raw)
