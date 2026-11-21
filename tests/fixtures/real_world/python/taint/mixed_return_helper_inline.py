import os
import shlex


def quote_either(flag, b):
    if flag:
        return shlex.quote(b)
    else:
        return b


def raw_first(flag, b):
    if not flag:
        return b
    return shlex.quote(b)


def quote_on_match(b):
    if b == "x":
        return shlex.quote(b)
    return b


def always_quote(b):
    return shlex.quote(b)


def either():
    c = os.environ["C"]
    s = quote_either(True, c)
    os.system("ls " + s)


def reversed_order():
    c = os.environ["C"]
    s = raw_first(True, c)
    os.system("ls " + s)


def on_match():
    c = os.environ["C"]
    s = quote_on_match(c)
    os.system("ls " + s)


def quoted():
    c = os.environ["C"]
    s = always_quote(c)
    os.system("ls " + s)
