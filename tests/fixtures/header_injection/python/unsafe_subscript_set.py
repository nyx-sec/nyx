# Unsafe: tainted request value flows into the bare-subscript header set
# `response.headers["X-Forwarded-By"] = lang`.  The LHS-subscript
# classification path matches `response.headers` / `resp.headers` as a
# HEADER_INJECTION sink so this form fires alongside the explicit
# `headers.add` / `set_cookie` method-call shapes.
from flask import request, make_response


def handler():
    lang = request.args.get("lang")
    response = make_response("ok")
    response.headers["X-Forwarded-By"] = lang
    return response
