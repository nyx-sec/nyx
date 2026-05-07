# Safe: query arg routed through `urlparse(...).netloc == ALLOWED`
# host-allowlist gate before passing to flask.redirect.  Recognised by
# PredicateKind::HostAllowlistValidated which clears Cap::OPEN_REDIRECT
# on the validated branch.
from flask import request, redirect
from urllib.parse import urlparse

ALLOWED_HOST = "trusted.example.com"


def handler():
    target = request.args.get("next")
    if urlparse(target).netloc == ALLOWED_HOST:
        return redirect(target)
    return redirect("/")
