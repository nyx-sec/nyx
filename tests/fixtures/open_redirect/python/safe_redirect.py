# Safe: query arg routed through `validate_redirect_url` allowlist before
# passing to flask.redirect.
from flask import request, redirect


def validate_redirect_url(raw):
    return raw if raw.startswith("/") else "/"


def handler():
    target = request.args.get("next")
    safe = validate_redirect_url(target)
    return redirect(safe)
