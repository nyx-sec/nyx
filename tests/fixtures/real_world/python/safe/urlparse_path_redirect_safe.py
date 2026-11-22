from urllib.parse import urlparse

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("next", "/")
    parsed = urlparse(target)
    # Only the path, query and fragment are kept: no scheme or host survives.
    dest = parsed.path or "/"
    if parsed.query:
        dest += "?" + parsed.query
    if parsed.fragment:
        dest += "#" + parsed.fragment
    return redirect(dest)
