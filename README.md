[![python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)]([https://github.com/psf/black](https://github.com/astral-sh/uv))
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

# Introduction

This is a fork of pyrad aiming to make it compatible with Python 3.12+
and introduce bug fixes and features.

The documentation below is from pyrad.

pyrad2 is an implementation of a RADIUS client/server as described in
RFC2865. It takes care of all the details like building RADIUS packets,
sending them and decoding responses.

Here is an example of doing a authentication request:

    from pyrad2.client import Client
    from pyrad2.dictionary import Dictionary
    import pyrad.packet

    srv = Client(server="localhost", secret=b"Kah3choteereethiejeimaeziecumi",
                 dict=Dictionary("dictionary"))

    # create request
    req = srv.CreateAuthPacket(code=pyrad2.packet.AccessRequest,
                               User_Name="wichert", NAS_Identifier="localhost")
    req["User-Password"] = req.PwCrypt("password")

    # send request
    reply = srv.SendPacket(req)

    if reply.code == pyrad2.packet.AccessAccept:
        print("access accepted")
    else:
        print("access denied")

    print("Attributes returned by server:")
    for i in reply.keys():
        print("%s: %s" % (i, reply[i]))

# Requirements & Installation

pyrad2 requires Python 3.12 and uses [uv](https://github.com/astral-sh/uv).

# Tests

Run `make test`

# Author, Copyright, Availability

pyrad was written by Wichert Akkerman \<<wichert@wiggy.net>\> and is
maintained by Christian Giese (GIC-de) and Istvan Ruzman (Istvan91).

This project is licensed under a BSD license.

Copyright and license information can be found in the LICENSE.txt file.

The current version and documentation can be found on pypi:
<https://pypi.org/project/pyrad2/>

Bugs and wishes can be submitted in the pyrad issue tracker on github:
<https://github.com/nicholasamorim/pyrad2/issues>
