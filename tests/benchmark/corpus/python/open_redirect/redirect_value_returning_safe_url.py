# Positive: `safe_url` and `url_safe_quote` return a value that is truthy for
# any input, so testing them validates nothing.
from flask import redirect, request


def a():
    u = request.args.get("next")
    if safe_url(u):
        return redirect(u)
    return redirect("/")


def b():
    u = request.args.get("next")
    if url_safe_quote(u):
        return redirect(u)
    return redirect("/")
