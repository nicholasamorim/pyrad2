from unittest.mock import MagicMock

import pytest

from pyrad2 import dedup, packet
from pyrad2.constants import PacketType
from pyrad2.server import RemoteHost, Server
from pyrad2.server_async import DatagramProtocolServer, ServerType

from .base import DummyServer


def _make_auth_packet(dictionary, *, ident=1, authenticator=b"0123456789ABCDEF"):
    """Build and re-parse an Access-Request so it carries authenticator/source."""
    raw = packet.AuthPacket(
        id=ident,
        secret=b"secret",
        authenticator=authenticator,
        dict=dictionary,
    ).request_packet()
    parsed = packet.AuthPacket(packet=raw, secret=b"secret", dict=dictionary)
    parsed.source = ("10.0.0.1", 12345)
    return parsed


class TestDedupKey:
    @pytest.fixture(autouse=True)
    def _inject_dictionary(self, full_dictionary):
        self.dictionary = full_dictionary

    def test_key_for_real_request(self):
        pkt = _make_auth_packet(self.dictionary)
        key = dedup.key_for(pkt)
        assert key.src_ip == "10.0.0.1"
        assert key.src_port == 12345
        assert key.code == int(PacketType.AccessRequest)
        assert key.identifier == 1
        assert key.request_authenticator == b"0123456789ABCDEF"

    def test_key_for_status_server_is_none(self):
        pkt = packet.StatusPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self.dictionary,
        )
        pkt.source = ("10.0.0.1", 12345)
        assert dedup.key_for(pkt) is None

    def test_key_for_missing_fields(self):
        class Stub:
            code = PacketType.AccessRequest

        assert dedup.key_for(Stub()) is None


class TestResponseCache:
    def setup_method(self):
        self.now = [1000.0]
        self.cache = dedup.ResponseCache(
            ttl=10.0, max_entries=3, clock=lambda: self.now[0]
        )
        self.key = dedup.DedupKey("10.0.0.1", 1, 1, 1, b"a" * 16)

    def test_miss(self):
        assert self.cache.lookup(self.key) is None

    def test_in_flight_then_cached(self):
        self.cache.mark_in_flight(self.key)
        assert self.cache.lookup(self.key) is dedup.IN_FLIGHT
        self.cache.record_reply(self.key, b"reply")
        assert self.cache.lookup(self.key) == b"reply"

    def test_ttl_expiry(self):
        self.cache.record_reply(self.key, b"reply")
        self.now[0] += 9.999
        assert self.cache.lookup(self.key) == b"reply"
        self.now[0] += 0.002
        assert self.cache.lookup(self.key) is None

    def test_lru_eviction(self):
        keys = [dedup.DedupKey("10.0.0.1", p, 1, p, bytes([p]) * 16) for p in range(5)]
        for k in keys:
            self.cache.record_reply(k, b"r-%d" % k.src_port)
        # Cap is 3, so the two oldest were evicted.
        assert len(self.cache) == 3
        assert self.cache.lookup(keys[0]) is None
        assert self.cache.lookup(keys[1]) is None
        assert self.cache.lookup(keys[2]) == b"r-2"
        assert self.cache.lookup(keys[4]) == b"r-4"

    def test_drop_in_flight_is_idempotent_and_noop_after_record(self):
        self.cache.mark_in_flight(self.key)
        self.cache.record_reply(self.key, b"reply")
        self.cache.drop_in_flight(self.key)
        assert self.cache.lookup(self.key) == b"reply"

    def test_consult_cache_actions(self):
        resends = []

        def resend(raw):
            resends.append(raw)

        # Miss → PROCESS and marked in-flight.
        action = dedup.consult_cache(self.cache, self.key, resend)
        assert action is dedup.DispatchAction.PROCESS
        assert self.cache.lookup(self.key) is dedup.IN_FLIGHT

        # In-flight retry → DROP, no resend.
        action = dedup.consult_cache(self.cache, self.key, resend)
        assert action is dedup.DispatchAction.DROP
        assert resends == []

        # After reply recorded, retry → RESENT with cached bytes.
        self.cache.record_reply(self.key, b"cached")
        action = dedup.consult_cache(self.cache, self.key, resend)
        assert action is dedup.DispatchAction.RESENT
        assert resends == [b"cached"]

    def test_consult_cache_with_no_cache_is_passthrough(self):
        action = dedup.consult_cache(None, self.key, lambda _: None)
        assert action is dedup.DispatchAction.PROCESS
        action = dedup.consult_cache(self.cache, None, lambda _: None)
        assert action is dedup.DispatchAction.PROCESS

    def test_mark_dropped_if_in_flight_records_no_reply_sentinel(self):
        # H6: a handler that completes without producing a reply must
        # leave a DROP sentinel so retransmissions within the TTL window
        # short-circuit to ``DispatchAction.DROP``.
        self.cache.mark_in_flight(self.key)
        self.cache.mark_dropped_if_in_flight(self.key)
        assert self.cache.lookup(self.key) is dedup.DROP_NOREPLY

        # And ``consult_cache`` maps that sentinel onto DROP — same
        # action a still-in-flight key would produce.
        resends: list[bytes] = []
        action = dedup.consult_cache(
            self.cache, self.key, lambda raw: resends.append(raw)
        )
        assert action is dedup.DispatchAction.DROP
        assert resends == []

    def test_mark_dropped_if_in_flight_is_noop_after_record_reply(self):
        # Successful handlers transition through ``record_reply`` which
        # clears the in-flight marker. Calling ``mark_dropped_if_in_flight``
        # in the ``finally`` clause must NOT overwrite the cached reply.
        self.cache.mark_in_flight(self.key)
        self.cache.record_reply(self.key, b"reply")
        self.cache.mark_dropped_if_in_flight(self.key)
        assert self.cache.lookup(self.key) == b"reply"

    def test_drop_sentinel_expires_with_ttl(self):
        self.cache.mark_in_flight(self.key)
        self.cache.mark_dropped_if_in_flight(self.key)
        assert self.cache.lookup(self.key) is dedup.DROP_NOREPLY

        self.now[0] += 9.999
        assert self.cache.lookup(self.key) is dedup.DROP_NOREPLY

        self.now[0] += 0.002
        assert self.cache.lookup(self.key) is None

    def test_record_reply_overrides_prior_drop_sentinel(self):
        # If an earlier attempt left a DROP sentinel and a later attempt
        # for the same key succeeds, the successful reply must
        # supersede the sentinel (rare but possible with concurrent
        # processing or operator-triggered cache clear scenarios).
        self.cache.mark_in_flight(self.key)
        self.cache.mark_dropped_if_in_flight(self.key)
        self.cache.mark_in_flight(self.key)
        self.cache.record_reply(self.key, b"late-reply")
        assert self.cache.lookup(self.key) == b"late-reply"


class _CaptureFd:
    def __init__(self):
        self.sent = []

    def sendto(self, data, target):
        self.sent.append((data, target))


class _CountingServer(Server):
    """Subclass that counts handler invocations — keeps Server.handle_auth_packet
    untouched so the rest of the suite isn't polluted by monkey-patching."""

    reply_code: int = PacketType.AccessAccept
    extra_attrs: dict = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.call_count = 0

    def handle_auth_packet(self, pkt):
        self.call_count += 1
        reply = self.create_reply_packet(pkt)
        reply.code = self.reply_code
        for key, builder in self.extra_attrs.items():
            reply[key] = builder(self.call_count)
        self.send_reply_packet(pkt.fd, reply)


class TestSyncServerDedup:
    @pytest.fixture(autouse=True)
    def _inject_dictionary(self, full_dictionary):
        self.dictionary = full_dictionary
        self.remote_host = RemoteHost("10.0.0.1", b"secret", "host")

    def _server(self, **kwargs):
        kwargs.setdefault("require_message_authenticator", False)
        return _CountingServer(
            hosts={"10.0.0.1": self.remote_host},
            dict=self.dictionary,
            **kwargs,
        )

    def _make_parsed_packet(self, ident=1, authenticator=b"0123456789ABCDEF"):
        parsed = _make_auth_packet(
            self.dictionary, ident=ident, authenticator=authenticator
        )
        parsed.fd = _CaptureFd()
        return parsed

    def test_retransmission_replays_cached_bytes(self):
        server = self._server()
        server.extra_attrs = {1: lambda n: [b"alice-%d" % n]}

        first = self._make_parsed_packet()
        server._handle_auth_packet(first)

        second = self._make_parsed_packet()
        second.fd = first.fd
        server._handle_auth_packet(second)

        assert server.call_count == 1
        assert len(first.fd.sent) == 2
        assert first.fd.sent[0][0] == first.fd.sent[1][0]

    def test_different_authenticator_is_not_a_duplicate(self):
        server = self._server()

        first = self._make_parsed_packet(authenticator=b"A" * 16)
        server._handle_auth_packet(first)
        second = self._make_parsed_packet(authenticator=b"B" * 16)
        server._handle_auth_packet(second)

        assert server.call_count == 2

    def test_dedup_disabled_runs_handler_every_time(self):
        server = self._server(dedup_enabled=False)
        for _ in range(3):
            server._handle_auth_packet(self._make_parsed_packet())
        assert server.call_count == 3
        assert server._dedup_cache is None

    def test_eap_state_is_preserved_across_retransmission(self):
        """RFC 5080: the cached reply must be byte-identical, so the EAP
        State attribute (which a fresh handler would regenerate) stays the
        same across retries."""
        server = self._server()
        server.reply_code = PacketType.AccessChallenge
        server.extra_attrs = {
            24: lambda n: [("state-%d" % n).encode()],
            79: lambda n: [b"\x01\x02\x00\x05\x01"],
        }

        first = self._make_parsed_packet()
        server._handle_auth_packet(first)
        replay = self._make_parsed_packet()
        replay.fd = first.fd
        server._handle_auth_packet(replay)

        assert server.call_count == 1
        assert first.fd.sent[0][0] == first.fd.sent[1][0]

    def test_failed_handler_drops_retransmission_within_ttl(self):
        """H6 regression: a handler that raises (or silently drops) must
        leave a DROP sentinel so retransmissions within the TTL window are
        suppressed instead of re-running the failed handler (RFC 5080
        §2.2.2). Previously the ``finally`` cleared the in-flight marker
        without recording anything, so retries went straight back into a
        clean cache."""

        class _RaisingServer(Server):
            def __init__(inner_self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                inner_self.call_count = 0

            def handle_auth_packet(inner_self, pkt):
                inner_self.call_count += 1
                raise RuntimeError("simulated handler failure")

        server = _RaisingServer(
            hosts={"10.0.0.1": self.remote_host},
            dict=self.dictionary,
            require_message_authenticator=False,
        )

        first = self._make_parsed_packet()
        with pytest.raises(RuntimeError):
            server._handle_auth_packet(first)
        assert server.call_count == 1
        assert first.fd.sent == [], "failed handler must not have sent a reply"

        # Retransmission of the same packet within the TTL window: dedup
        # cache returns DROP, handler must NOT re-run, fd must NOT be sent.
        retry = self._make_parsed_packet()
        retry.fd = first.fd
        server._handle_auth_packet(retry)
        assert server.call_count == 1, "failed handler must not re-run on retry"
        assert retry.fd.sent == [], "retry must be dropped silently"

    def test_failed_handler_drop_expires_with_ttl(self):
        """The DROP sentinel respects the cache TTL — once it expires, a
        retransmission falls through to a fresh handler invocation."""

        clock = [1000.0]

        class _RaisingOnceServer(Server):
            def __init__(inner_self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                inner_self.call_count = 0

            def handle_auth_packet(inner_self, pkt):
                inner_self.call_count += 1
                if inner_self.call_count == 1:
                    raise RuntimeError("simulated handler failure")
                # Second attempt succeeds.
                reply = inner_self.create_reply_packet(pkt)
                reply.code = PacketType.AccessAccept
                inner_self.send_reply_packet(pkt.fd, reply)

        # Inject a clock the test controls so the TTL window is
        # deterministic and the test doesn't sleep.
        cache = dedup.ResponseCache(ttl=5.0, clock=lambda: clock[0])
        server = _RaisingOnceServer(
            hosts={"10.0.0.1": self.remote_host},
            dict=self.dictionary,
            require_message_authenticator=False,
            dedup_cache=cache,
        )

        first = self._make_parsed_packet()
        with pytest.raises(RuntimeError):
            server._handle_auth_packet(first)
        assert server.call_count == 1

        # Within the TTL: retry dropped silently.
        clock[0] += 1.0
        retry = self._make_parsed_packet()
        retry.fd = first.fd
        server._handle_auth_packet(retry)
        assert server.call_count == 1
        assert retry.fd.sent == []

        # Past the TTL: retry falls through and the handler succeeds.
        clock[0] += 10.0
        post_ttl = self._make_parsed_packet()
        post_ttl.fd = _CaptureFd()
        server._handle_auth_packet(post_ttl)
        assert server.call_count == 2
        assert len(post_ttl.fd.sent) == 1


class TestAsyncServerDedup:
    @pytest.fixture(autouse=True)
    def _inject_dictionary(self, full_dictionary):
        self.dictionary = full_dictionary
        self.remote_host = RemoteHost("10.0.0.1", b"secret", "host")

    def _protocol_for(self, server):
        protocol = DatagramProtocolServer(
            ip="10.0.0.1",
            port=1812,
            server=server,
            server_type=ServerType.Auth,
            hosts={"10.0.0.1": self.remote_host},
            request_callback=server._request_handler,
        )
        protocol.transport = MagicMock()
        return protocol

    def _request_bytes(self, ident=1, authenticator=b"0123456789ABCDEF"):
        return packet.AuthPacket(
            id=ident,
            secret=b"secret",
            authenticator=authenticator,
            dict=self.dictionary,
        ).request_packet()

    def test_retransmission_replays_cached_bytes(self):
        call_count = [0]

        class DedupServer(DummyServer):
            def handle_auth_packet(inner_self, protocol, pkt, addr):
                call_count[0] += 1
                reply = inner_self.create_reply_packet(pkt)
                reply[1] = [b"alice-%d" % call_count[0]]
                protocol.send_response(reply, addr)

        server = DedupServer(
            dictionary=self.dictionary,
            hosts={"10.0.0.1": self.remote_host},
            require_message_authenticator=False,
            enable_pkt_verify=False,
        )
        protocol = self._protocol_for(server)

        data = self._request_bytes()
        addr = ("10.0.0.1", 12345)
        protocol.datagram_received(data, addr)
        first_bytes = protocol.transport.sendto.call_args.args[0]

        protocol.datagram_received(data, addr)
        second_bytes = protocol.transport.sendto.call_args.args[0]

        assert call_count[0] == 1
        assert protocol.transport.sendto.call_count == 2
        assert first_bytes == second_bytes

    def test_dedup_disabled_runs_handler_every_time(self):
        call_count = [0]

        class DedupServer(DummyServer):
            def handle_auth_packet(inner_self, protocol, pkt, addr):
                call_count[0] += 1
                reply = inner_self.create_reply_packet(pkt)
                protocol.send_response(reply, addr)

        server = DedupServer(
            dictionary=self.dictionary,
            hosts={"10.0.0.1": self.remote_host},
            dedup_enabled=False,
            require_message_authenticator=False,
            enable_pkt_verify=False,
        )
        protocol = self._protocol_for(server)

        data = self._request_bytes()
        addr = ("10.0.0.1", 12345)
        protocol.datagram_received(data, addr)
        protocol.datagram_received(data, addr)
        assert call_count[0] == 2
        assert server._dedup_cache is None


# Quiet unused-import linters: pytest is the explicit import marker for
# pytest-style files even when no fixture is referenced.
_ = pytest
