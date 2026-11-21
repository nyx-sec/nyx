import os
import shlex


def maybe_quote(value, strict):
    if strict:
        return shlex.quote(value)
    return value


def run(name):
    cmd = os.environ["CMD"]
    arg = maybe_quote(cmd, name == "x")
    os.system("ls " + arg)
