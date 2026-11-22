from urllib.parse import urlparse

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("next", "/")
    parsed = urlparse(target)
    dest = parsed.path
    if not dest.startswith("/") or dest.startswith("//") or dest.startswith("/\\"):
        dest = "/"
    return redirect(dest)
