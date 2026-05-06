# Safe: request arg routed through `strip_crlf` (a registered
# HEADER_INJECTION sanitizer) before the subscript-set, so
# taint-header-injection stays clean.
from flask import request, make_response


def strip_crlf(raw):
    return raw.replace("\r", "").replace("\n", "")


def handler():
    lang = request.args.get("lang")
    response = make_response("ok")
    response.headers["X-Forwarded-By"] = strip_crlf(lang)
    return response
