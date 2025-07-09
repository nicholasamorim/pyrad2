Changelog
=========


1.1 - Jul 9, 2025

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
