# Phase 08 (Track J.6) — Python HEADER_INJECTION vuln fixture.
#
# The function assigns the attacker-controlled `value` directly into
# a Flask response's `Set-Cookie` header via `Response.headers
# .__setitem__`.  A payload carrying `\r\nSet-Cookie: nyx-injected=pwn`
# splits the single header into two on the wire.
from flask import Response


def run(value):
    response = Response("ok")
    response.headers["Set-Cookie"] = value
    return response
