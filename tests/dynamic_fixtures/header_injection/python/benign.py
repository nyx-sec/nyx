# Phase 08 (Track J.6) — Python HEADER_INJECTION benign control fixture.
#
# Same shape as `vuln.py` but URL-encodes the value via
# `urllib.parse.quote` first, so CRLF bytes land as `%0D%0A` and the
# wire keeps a single header.
from urllib.parse import quote
from flask import Response


def run(value):
    response = Response("ok")
    response.headers["Set-Cookie"] = quote(value, safe="")
    return response
