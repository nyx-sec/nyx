# Safe: request arg routed through `strip_crlf` before being added to the
# response headers.
from flask import request, make_response


def strip_crlf(raw):
    return raw.replace("\r", "").replace("\n", "")


def handler():
    lang = request.args.get("lang")
    safe = strip_crlf(lang)
    resp = make_response("ok")
    resp.headers.add("X-Lang", safe)
    return resp
