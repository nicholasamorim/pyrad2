# Installing

``` bash title="Install with pip"
$ pip install pyrad2
```

``` bash title="Install with uv"
$ uv add pyrad2
```

# How does pyrad2 work

pyrad2 allows you to build servers and clients for the [RADIUS](https://en.wikipedia.org/wiki/RADIUS) protocol.

It is not meant to be a standalone implementation like [FreeRADIUS](https://freeradius.org), but rather as a tool to allow you to build your own server and client.

## Learning by running

The fastest way to understand pyrad2 is to run a working exchange end-to-end and watch what crosses the wire. The repository ships two complementary surfaces:

| Folder | Purpose | When to use |
| --- | --- | --- |
| [`examples/`](https://github.com/nicholasamorim/pyrad2/tree/master/examples) | Operational scripts — a server, a client, intended to be **copied into your own project** and edited. | When you're ready to write your own integration. |
| [`scenarios/`](https://github.com/nicholasamorim/pyrad2/tree/master/scenarios) | Single-process end-to-end demos — one event loop runs both a server **and** a client so the full exchange shows up on a single log. **Not meant to be edited.** | When you want to understand what a flow looks like, top to bottom. |

Each scenario is one `python scenarios/<name>.py` away:

``` bash title="Run individual scenarios"
make scenario_auth     # Access-Request → Access-Accept (UDP, RFC 2865)
make scenario_acct     # Accounting-Request → Accounting-Response
make scenario_coa      # CoA-Request → CoA-ACK (RFC 5176)
make scenario_status   # Status-Server health check (RFC 5997)
make scenario_radsec   # RadSec (RFC 6614) — mutual TLS, Access-Request
make demo              # all five sequentially
```

The RadSec scenario uses the test certificates that ship in
`examples/certs/` and exercises the same surface as UDP scenarios with
mutual TLS layered on top — useful for confirming that the dictionary,
encoding, and decoding features work identically across transports.

### Wire-level visibility: PYRAD2_TRACE

The scenarios become a protocol-learning tool when paired with the `PYRAD2_TRACE` environment variable. Set it to `1` (or `true`/`yes`/`on`) on any script — scenario, example, or your own code — and pyrad2 dumps every packet that flows through `request_packet`, `reply_packet`, and `decode_packet`:

``` bash title="Watch the bytes"
PYRAD2_TRACE=1 make scenario_auth
```

Each dump shows direction (`→` outgoing, `←` incoming), packet type, id, length, authenticator, the decoded AVPs, and an xxd-style hex view of the raw bytes:

```
[pyrad2 trace] → AccessRequest id=5 len=39
    authenticator: de0f04abde127b093c5e456b9f51ed81
    attributes:
      User-Name: ['alice']
      NAS-IP-Address: ['192.168.1.10']
      Service-Type: ['Login-User']
    raw:
        0000  01 05 00 27 de 0f 04 ab de 12 7b 09 3c 5e 45 6b  ...'......{.<^Ek
        0010  9f 51 ed 81 01 07 61 6c 69 63 65 04 06 c0 a8 01  .Q....alice.....
        0020  0a 06 06 00 00 00 01                             .......
```

It is gated by the env var, costs nothing when off, and routes through the same `loguru` pipeline as the rest of pyrad2 — so you can filter, redirect, or format it like any other log message in your application.

`PYRAD2_TRACE` is the recommended way to debug "why didn't this packet do what I expected?" without dropping to Wireshark.

## RADIUS Concepts

### Dictionary 

For the purpose of using pyrad2, the most important concept is the _Dictionary_. The dictionary is an actual file on the filesystem.

!!! note

    Dictionary files are textfiles with one command per line.

RADIUS uses dictionaries to define the attributes that can
be used in packets. The Dictionary class stores the attribute definitions from one or more dictionary files and allows Server/Client to understand what an _attribute code_ means.

Here's an example of how it looks:

```
ATTRIBUTE	User-Name		    1	string
ATTRIBUTE	User-Password		2	string
ATTRIBUTE	CHAP-Password		3	octets
```

You can find a reference dictionary file [here](https://github.com/nicholasamorim/pyrad2/blob/master/examples/dictionary). Another dictionary is provided [here](https://github.com/nicholasamorim/pyrad2/blob/master/examples/dictionary.freeradius) with FreeRADIUS vendor-specific attributes.

For our example, download _both files_ and place it into your project folder.

When you see code like this:

``` py title="Loading a dictionary"
dictfile = dictionary.Dictionary("dictionary")
```

You are actually passing a _path_ to a file (or a [file-like object](https://docs.python.org/3/library/io.html)) called `dictionary`, so make sure the file you pass is accessible from your code and it's a valid dictionary file.

#### Supported dictionary features

pyrad2 aims to load real-world FreeRADIUS dictionaries without modification.

A runnable demo of every feature below lives in
[`examples/dictionary_features.py`](https://github.com/nicholasamorim/pyrad2/blob/master/examples/dictionary_features.py),
backed by [`examples/dictionary.extended`](https://github.com/nicholasamorim/pyrad2/blob/master/examples/dictionary.extended).
Run it with `make dictionary_features`.

**Data types**: `string`, `octets`, `integer`, `signed`, `short`, `byte`,
`integer64`, `date`, `ipaddr`, `ipv6addr`, `ipv6prefix`, `ifid` (RFC 3162
8-byte Interface-Id), `ether` (RFC 6911 MAC address), `abinary` (Ascend
filter format), `tlv` (one level of nesting), `extended` and
`long-extended` (RFC 6929 wrappers).

**Attribute options** (comma-separated, after the type column):

- `has_tag` — attribute carries a one-byte tag prefix (RFC 2868).
- `encrypt=N` — apply encryption flavour 1, 2, or 3.
- `concat` — values longer than 253 bytes split across multiple AVPs on
  the wire and concatenate on decode (RFC 7268 §3.6). Typical for
  `EAP-Message` and `CHAP-Challenge`.

**Vendor format** (`VENDOR Name 9 format=type_len,len_len`): the per-vendor
VSA wire format is honored end-to-end. `type_len` may be 1, 2, or 4 bytes
and `len_len` may be 0, 1, or 2 bytes. The default when no `format=` is
declared follows RFC 2865 §5.26 (`1,1`).

**RFC 6929 extended attributes** (types 241–246): declare the wrapper as
`extended` (241–244) or `long-extended` (245–246), then add sub-attributes
using dotted-code notation:

```
ATTRIBUTE Extended-Attribute-1  241    extended
ATTRIBUTE Frag-Status           241.1  integer
ATTRIBUTE Auth-Lifetime         241.2  integer

ATTRIBUTE Extended-Attribute-5  245    long-extended
ATTRIBUTE WiMAX-Blob            245.1  octets
```

Values are accessed by name on the packet (`pkt["Frag-Status"] = 5`) and
read back through the parent (`pkt["Extended-Attribute-1"]` returns a
dict of sub-attribute name → values). Long-extended values larger than
251 bytes are fragmented across multiple AVPs on send and reassembled on
receive — callers see one logical value either way.

**Extended-Vendor-Specific** (EVS, RFC 6929 §2.3): the `evs` type marks a
sub-attribute of an extended wrapper that carries a vendor-specific
payload. FreeRADIUS's `BEGIN-VENDOR <name> parent=<evs-attr>` syntax
scopes the vendor's attributes underneath:

```
ATTRIBUTE Extended-Attribute-1        241     extended
ATTRIBUTE Extended-Vendor-Specific-1  241.26  evs

VENDOR Example 12345

BEGIN-VENDOR Example parent=Extended-Vendor-Specific-1
ATTRIBUTE Example-Attr-1  1  string
ATTRIBUTE Example-Attr-2  2  integer
END-VENDOR Example
```

EVS attributes are accessed by name (`pkt["Example-Attr-1"] = "hello"`).
The wire encoding wraps the vendor id and vendor type into the extended
payload; long-extended EVS values are fragmented and reassembled the same
way as plain long-extended attributes.

**Not yet supported**: TLV nesting deeper than two levels.