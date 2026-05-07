# Safe: query arg routed through `ensure_relative_url` which enforces a
# leading `/` and rejects scheme-prefixed values (relative-only path).
from flask import request, redirect


def ensure_relative_url(raw):
    if not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//"):
        return "/"
    return raw


def handler():
    target = request.args.get("next")
    safe = ensure_relative_url(target)
    return redirect(safe)
