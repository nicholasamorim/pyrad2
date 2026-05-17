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

**Data types**: `string`, `octets`, `integer`, `signed`, `short`, `byte`,
`integer64`, `date`, `ipaddr`, `ipv6addr`, `ipv6prefix`, `ifid` (RFC 3162
8-byte Interface-Id), `ether` (RFC 6911 MAC address), `abinary` (Ascend
filter format), and `tlv` (one level of nesting).

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

**Not yet supported**: RFC 6929 extended / long-extended attributes
(types 241–246) and TLV nesting deeper than two levels.