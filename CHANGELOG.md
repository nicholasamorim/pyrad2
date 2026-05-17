Changelog
=========

2.3 - Unreleased
----------------

# Deduplication (RFC 5080)

- RFC 5080 §2.2.2 duplicate detection and response cache for `Server` and
  `ServerAsync`. Retransmitted Access/Accounting/CoA/Disconnect-Requests now
  replay the original reply bytes instead of re-running the handler — critical
  for EAP `State` continuity and to avoid double-counting accounting updates.
  Enabled by default; tune via `dedup_enabled`, `dedup_ttl`, `dedup_max_entries`,
  or `dedup_cache=` on the server constructor.

2.2 - May 17, 2025
------------------

- Add scenarios for a better development experience.
- Add support for Extended attributes (types 241–244) and Long-Extended attributes (types 245–246)
- Add support for RFC 6929
- Add support for EVS (Extended-Vendor-Specific) attributes
- BEGIN-VENDOR <name> parent=<evs-attr> now accepted
- Add encoders/decoders for ifid (RFC 3162) and ether (RFC 6911)

2.1 - May 16, 2025
------------------

# Breaking Changes (RadSec onyly)
  - Default flips: deployments on TLS 1.1 or with non-matching cert SANs now fail. Pass custom config to avoid this behaviour.
  - Stricter MA + connection reuse default. Peers sending malformed MAs are now rejected. Use `reuse_connection=False` to disable it.

- RadSec client now defaults to hostname validation and TLS 1.2+
- RadSec server now defaults to mutual TLS client-cert verification and TLS 1.2+
- Removed the hard-coded legacy cipher list path
- Callers can still pass a custom OpenSSL cipher string explicitly
- Added SHA-256 certificate fingerprint normalization/matching helper
- Added optional server certificate and client certificate fingerprint allowlists
- RadSecServer(verify_packet=True) now dispatches to the correct packet verifier
- Updated RadSec server handling to read packets in a loop on each TLS connection instead of processing only one packet
- Added configurable connection_read_timeout and max_packets_per_connection
- RadSec client to reuse one TLS connection by default
- Added configurable client options for reuse_connection=False for old one-connection-per-packet behavior
- Added reconnect_backoff
- Existing timeout now wraps connect, write/drain, and response
- Added close() and async context-manager support for reusable RadSec clients
- RadSecServer no longer requires handle_coa() or handle_disconnect() either
- RadSec now has enable_coa and enable_disconnect flags. They default to True for compatibility, but disabled requests get NAKed cleanly

# Message Authenticator

- Fix reply Message-Authenticator verification to validate the reply, not the request
- Validate Message-Authenticator whenever the attribute is present
- Require Message-Authenticator for packets containing EAP-Message
- Add opt-in server policy to require Message-Authenticator on all packets
- Automatically add Message-Authenticator to EAP requests and protected replies

# Status-Server

- Add StatusPacket creation and parsing
- Add sync, async, and RadSec Status-Server handling
- Require Message-Authenticator on Status-Server requests
- Reply to auth Status-Server checks with Access-Accept
- Reply to accounting Status-Server checks with Accounting-Response
- Avoid invoking normal auth/accounting handlers for health checks
- Add UDP and RadSec status examples
- Document Status-Server usage across client and server APIs

# Improvements to COA and Disconnect

- ServerAsync no longer requires handle_coa_packet() or handle_disconnect_packet() on every subclass
- Default UDP async behavior now replies with CoA-NAK or Disconnect-NAK
- RadSecServer no longer requires handle_coa() or handle_disconnect() either
- RadSec now has enable_coa and enable_disconnect flags. They default to True for compatibility, but disabled requests get NAKed cleanly
- NAKs include RFC 5176 Error-Cause = 406 / Unsupported Extension

# Feature Parity

- Fix async client retry/timeout correctness and add EAP-MD5 parity The async retry loop in client_async.py had two latent bugs and lagged the sync client on EAP-MD5 handling. Both bugs were silently invisible because no test covered the retry path.
- Retries raised AttributeError inside an asyncio task and never re-sent on the wire. Changed to request_packet() to match the initial send.
- Fixed timeout math
- EAP-MD5 added to async client and all 3 clients (sync, async and radsec) call the same shared helper

2.0 - Apr 6, 2026
-----------------

- *Breaking Changes*: The entire codebase has been converted from CamaleCase to use Python's snake case.
- Enforce Message-Authenticator if present
- Ascend-Data-Filter now supports `delete` keyword
- Several fixes, more typing

# Breaking Changes

- Converted BiDict to Python standard

1.2.0 - Jul 22, 2025
--------------------

# Features

- Use selectors in place of select on Windows

1.1.1 - Jul 9, 2025
--------------------

# Fixes

- `ssl.CERT_REQUIRED` is enabled by default.

1.1.0 - Jul 9, 2025
--------------------

# Features

- add RadSec (RFC 6614) support. _Experimental_
- Ensure all examples in the `examples` folder are working.

# Refactors

- Move constants to `pyrad2.constants`
- Move several global variables into `pyrad2.constants`.
- EAP and Packet types are now acessed via PacketType enum in `constants` module. 
- `DATATYPES` has moved to `constants.py`
- Consolidate all exceptions under `exceptions.py`. All of the libraries exceptions inherit from `RadiusException` now.

# Testing

- Improve typing and testing coverage.


# Documentation

- Improve navigation.
- Add RadSec pages.

# Chore

- Add several testing options to Makefile.
- Add test/example SSL certificates for server and client.

1.0 - Jul 7, 2025
-------------------

- Extensively refactored code
- Remove legacy Python 2.x/3.x and support only Python 3.12
- Add typing support to the whole codebase using mypy.
- Poetry phased out in favour of uv
- [#213](https://github.com/pyradius/pyrad/pull/213) in PyRad fixed.
- [#210](https://github.com/pyradius/pyrad/pull/210) in PyRad merged.
- Remove `nose` as it's unmaintained and replace it with pytest. `pytest-sugar` being used for pretty test output.
- Added loguru dependency for better log formatting.
- Modernize AsyncIO code.
- Update README.md
