import os
import subprocess
from unittest.mock import mock_open

# Callees that merely end in an acquire name are not acquires.  Only the
# last two functions hold a real handle that is never closed.
# Expected: exactly two state-resource-leak findings (pipe_leak, real_leak).


def disc(client):
    res = client.disconnect()
    return str(res)


def reconn(client):
    status = client.reconnect()
    return str(status)


def ensure(store):
    handle = store._ensure_open()
    return str(handle)


def is_open_check(door):
    st = door.is_open()
    return str(st)


def run(cmd):
    proc = subprocess.Popen(cmd)
    proc.communicate()


def fake():
    m = mock_open(read_data="x")
    return str(m)


def pipe_leak(cmd):
    out = os.popen(cmd)
    print(out.read())


def real_leak(p):
    f = open(p)
    print(f.read())
