# Unsafe: Flask response.headers.add receives a value built from request
# args.  HEADER_INJECTION fires on the value argument.
from flask import request, make_response


def handler():
    lang = request.args.get("lang")
    resp = make_response("ok")
    resp.headers.add("X-Lang", lang)
    return resp
