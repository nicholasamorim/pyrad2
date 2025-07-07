Changelog
=========

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
