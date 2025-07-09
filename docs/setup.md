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