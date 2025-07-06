[![image](https://github.com/nicholasamorim/pyrad2/workflows/Python%203.X%20test/badge.svg?branch=master)](https://github.com/nicholasamorim/pyrad2/actions?query=workflow)

[![image](https://coveralls.io/repos/github/nicholasamorim/pyrad2/badge.svg?branch=master)](https://coveralls.io/github/nicholasamorim/pyrad2?branch=master)

[![image](https://img.shields.io/pypi/v/pyrad.svg)](https://pypi.python.org/pypi/pyrad)

[![image](https://img.shields.io/pypi/pyversions/pyrad.svg)](https://pypi.python.org/pypi/pyrad)

[![image](https://img.shields.io/pypi/dm/pyrad.svg)](https://pypi.python.org/pypi/pyrad)

[![Documentation Status](https://readthedocs.org/projects/pyradius-pyrad/badge/?version=latest)](https://pyradius-pyrad.readthedocs.io/en/latest/?badge=latest)

[![image](https://img.shields.io/pypi/l/pyrad.svg)](https://pypi.python.org/pypi/pyrad)

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

pyrad2 requires Python 3.12 and uses [uv]{.title-ref}.

# Tests

Run [make test]{.title-ref}

# Author, Copyright, Availability

pyrad was written by Wichert Akkerman \<<wichert@wiggy.net>\> and is
maintained by Christian Giese (GIC-de) and Istvan Ruzman (Istvan91).

This project is licensed under a BSD license.

Copyright and license information can be found in the LICENSE.txt file.

The current version and documentation can be found on pypi:
<https://pypi.org/project/pyrad/>

Bugs and wishes can be submitted in the pyrad issue tracker on github:
<https://github.com/nicholasamorim/pyrad2/issues>
