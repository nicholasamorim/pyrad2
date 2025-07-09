# Making RADIUS Requests

- [Making RADIUS Requests](#making-radius-requests)
- [UDP Requests](#udp)
  - [Sending an authentication packet](#sending-an-authentication-packet)
- [Setting attributes](#setting-attributes)
- [RadSec](#radsec)



# UDP

To instantiate a client you can use `ClientAsync`. A sync version is also provided in `pyrad2.client`.

!!! Note

    Both your server and client must be loaded with the _same_ dictionary. Remember, this is how the client and server can understand what it means to use a given attribute code.


``` py title="Instantiating a client"
from pyrad2.client_async import ClientAsync
from pyrad2.dictionary import Dictionary


client = ClientAsync(
    server="localhost",
    secret=b"Kah3choteereethiejeimaeziecumi",
    timeout=4,
    dict=Dictionary("dictionary"),
)
```

!!! Note

    In real code, we would never pass the secret hardcoded.

## Sending an authentication packet

You can find the example for an auth request [here](https://github.com/nicholasamorim/pyrad2/blob/master/examples/auth_async.py).

``` bash title="Making an authentication request"
$ uv run auth_async.py  # make sure the server is running before

2025-07-07 13:06:36.984 | INFO     | pyrad2.client_async:connection_made:112 - [localhost:3799] Transport created with binding in ::1:62525
2025-07-07 13:06:36.984 | INFO     | pyrad2.client_async:connection_made:112 - [localhost:1812] Transport created with binding in 127.0.0.1:8000
2025-07-07 13:06:36.984 | INFO     | pyrad2.client_async:connection_made:112 - [localhost:1813] Transport created with binding in ::1:64970
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:87 - Access accepted
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:91 - Attributes returned by server:
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:93 - Service-Type: ['Framed-User']
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:93 - Framed-IP-Address: ['192.168.0.1']
2025-07-07 13:06:36.989 | INFO     | __main__:test_auth1:93 - Framed-IPv6-Prefix: ['fc66::/64']
```

This is the core code that creates the packet.  

``` py
def create_request(client, user):
    req = client.CreateAuthPacket(User_Name=user)

    req["NAS-IP-Address"] = "192.168.1.10"
    req["NAS-Port"] = 0
    req["Service-Type"] = "Login-User"
    req["NAS-Identifier"] = "trillian"
    req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
    req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
    req["Framed-IP-Address"] = "10.0.0.100"

    return req
```

You can find a list of standard RADIUS attributes [here](https://datatracker.ietf.org/doc/html/rfc2865#page-22). Note that these do not include vendor-specific attributes.

# Setting attributes

To set attributes in the `Client` object, you need to replace underscores with hyphens. So instead of `User_Name`, you use `User-Name`. The former is used in python code and the latter is used directly in the underlying data.

``` py title="Naming inconsistencies"
req = srv.CreateAuthPacket(User_Name="wichert")

# But if acessing the attributes directly
req["User-Name"] = "wichert2"
req["NAS-IP-Address"] = "192.168.1.10"

```


[Suggestion]: Add some description for the valid arguments that could be passed to CreateAuthPacket.


# RadSec

!!! Note

    This feature is currently *experimental*.

To use RadSec client, you must import from `pyrad2.client.radsec.client`

``` py title="Creating a RadSec client"
client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=Dictionary("/dictionary"),
    certfile="certs/ca/ca.cert.pem",
    keyfile="certs/client/client.cert.pem"
    certfile_server="certs/client/client.key.pem"
)
```

You can find an example implementation [here](https://github.com/nicholasamorim/pyrad2/blob/master/examples/auth_radsec.py).