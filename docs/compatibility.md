# Migrating from pyrad

pyrad2 is a friendly fork of [pyrad](https://github.com/pyradius/pyrad). It is **not** a drop-in replacement.

## Breaking changes since 2.0

- **Python 3.12 or newer** is required.
- **Twisted integration is gone.** Use the asyncio-based `ServerAsync` / `ClientAsync` instead.
- **The entire codebase is snake_case.** PascalCase method names like `CreateAuthPacket` have been renamed to `create_auth_packet`. Adapt your call sites accordingly.

For everything new in the fork (RadSec, RADIUS/1.1, Status-Server, dedup, Message-Authenticator enforcement, FreeRADIUS dictionary fidelity, `PYRAD2_TRACE`), see the [home page](index.md) or the [release notes](https://github.com/nicholasamorim/pyrad2/releases).
