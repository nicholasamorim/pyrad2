"""Dictionary File

Implements an iterable file format that handles the
RADIUS $INCLUDE directives behind the scene.
"""

import io
import os
from typing import Optional, Self


class _Node:
    """Dictionary file node

    A single dictionary file.
    """

    __slots__ = ("name", "lines", "current", "length", "dir")

    def __init__(self, fd: io.TextIOWrapper, name: str, parentdir: str):
        self.lines = fd.readlines()
        self.length = len(self.lines)
        self.current = 0
        self.name = os.path.basename(name)
        path = os.path.dirname(name)
        if os.path.isabs(path):
            self.dir = path
        else:
            self.dir = os.path.join(parentdir, path)

    def next(self) -> Optional[str]:
        if self.current >= self.length:
            return None
        self.current += 1
        return self.lines[self.current - 1]


class DictFile:
    """Dictionary file class

    An iterable file type that handles $INCLUDE
    directives internally.
    """

    __slots__ = "stack"

    def __init__(self, fil: str | io.TextIOWrapper) -> None:
        """
        @param fil: a dictionary file to parse
        @type fil: string or file
        """
        self.stack: list[_Node] = []
        self.__read_node(fil)

    def __read_node(self, fil: str | io.TextIOWrapper) -> None:
        parentdir = self.__cur_dir()
        if isinstance(fil, str):
            if os.path.isabs(fil):
                fname = fil
            else:
                fname = os.path.join(parentdir, fil)
            fd = open(fname)
            node = _Node(fd, fil, parentdir)
            fd.close()
        else:
            node = _Node(fil, "", parentdir)
        self.stack.append(node)

    def __cur_dir(self) -> str:
        if self.stack:
            return self.stack[-1].dir
        else:
            return os.path.realpath(os.curdir)

    def __get_include(self, line: str) -> Optional[str]:
        line = line.split("#", 1)[0].strip()
        tokens = line.split()
        if tokens and tokens[0].upper() == "$INCLUDE":
            return " ".join(tokens[1:])
        else:
            return None

    def line(self) -> int:
        """Returns line number of current file"""
        if self.stack:
            return self.stack[-1].current
        else:
            return -1

    def file(self) -> str:
        """Returns name of current file"""
        if self.stack:
            return self.stack[-1].name
        else:
            return ""

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> str:
        while self.stack:
            line = self.stack[-1].next()
            if line is None:
                self.stack.pop()
            else:
                inc = self.__get_include(line)
                if inc:
                    self.__read_node(inc)
                else:
                    return line
        raise StopIteration

    next = __next__  # BBB for python <3
