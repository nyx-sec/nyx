# Safe: query arg is only redirected to when it is a site-relative path.
# A `startswith("/")` check that also rejects the protocol-relative `//`
# form is recognised as a relative-URL guard.
from flask import request, redirect


def handler():
    target = request.args.get("next")
    if target.startswith("/") and not target.startswith("//"):
        return redirect(target)
    return redirect("/")
