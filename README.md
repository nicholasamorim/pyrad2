<img src="docs/logo.png" width="10%" height="auto"> 

[![Tests](https://github.com/nicholasamorim/pyrad2/actions/workflows/python-test.yml/badge.svg)](https://github.com/miraclesupernova/stickystack/actions/workflows/django.yml)
[![python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)]([https://github.com/psf/black](https://github.com/astral-sh/uv))
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

pyrad2 is an implementation of a RADIUS client/server as described in RFC2865 and of RADSEC client/server as described in RFC6614. It takes care of all the details like building RADIUS packets,sending them and decoding responses.

**Documentation can be found [here](https://nicholasamorim.github.io/pyrad2/).**

# Introduction

[pyrad2](https://github.com/nicholasamorim/pyrad2) is an implementation of a RADIUS client/server as described in RFC2865. It takes care of all the details like building RADIUS packets, sending them and decoding responses.

What this fork does:
   
- Adds RadSec (RFC 6614) support (Experimental)
- Supports only Python 3.12+
- Extensive typing
- Increased test coverage
- New bug fixes

Note that this is _not_ a stand-alone Radius implementation like [FreeRadius](https://www.freeradius.org). You are supposed to inherit the server classes and code your own behind-the-scenes implementation. This package allows you to code your business logic on top of it.

# Requirements & Installation

pyrad2 requires Python 3.12 and uses [uv](https://github.com/astral-sh/uv). On a Mac, you can simply run `brew install uv`.

# Examples

See the [Getting Started guide](https://nicholasamorim.github.io/pyrad2/getting_started/) for a better overview.

There are a few examples in the `examples` folder. You can either install pyrad2 and use the examples or clone the repo. If you clone the repo, make commands are useful.

The easiest way to start a server is by running `make server`. This will run the example server in `examples/server_async.py`.

If you want to see a request in action, leave the server running, open another terminal and type `make auth`. Several other commands are available such as `make server_radsec`, `make server_coa`, `make_acct`, etc.

# Tests

Run `make test`.

# Author, Copyright, Availability

pyrad2 is currently maintaned by Nicholas Amorim \<<nicholas@santos.ee\>.

pyrad was written by Wichert Akkerman \<<wichert@wiggy.net>\> and is
maintained by Christian Giese (GIC-de) and Istvan Ruzman (Istvan91).

This project is licensed under a BSD license.

Copyright and license information can be found in the LICENSE.txt file.

The current version and documentation can be found on pypi:
<https://pypi.org/project/pyrad2/>

Bugs and wishes can be submitted in the pyrad issue tracker on github:
<https://github.com/nicholasamorim/pyrad2/issues>
