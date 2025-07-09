# pyrad2 

<img src="logo.png" width="10%" height="auto"> 

[![Tests](https://github.com/nicholasamorim/pyrad2/actions/workflows/python-test.yml/badge.svg)](https://github.com/miraclesupernova/stickystack/actions/workflows/django.yml)
[![python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)]([https://github.com/psf/black](https://github.com/astral-sh/uv))
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

[pyrad2](https://github.com/nicholasamorim/pyrad2) is an implementation of a RADIUS client/server as described in RFC2865. It takes care of all the details like building RADIUS packets, sending them and decoding responses.

What this fork does:
   
- Supports only Python 3.12+
- Extensive typing
- Increased test coverage
- New bug fixes
- Experimental RadSec support
    
PRs are _very_ welcome. For more information on what has changed, see our [releases](https://github.com/nicholasamorim/pyrad2/releases) page.

See the [Getting Started](/getting_started) guide for a tutorial on how to get started.