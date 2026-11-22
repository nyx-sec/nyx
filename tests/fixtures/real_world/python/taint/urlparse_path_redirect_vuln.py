from urllib.parse import urlparse

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("next", "/")
    parsed = urlparse(target)
    # The path of "////evil.com" is "//evil.com", a protocol-relative URL.
    dest = parsed.path
    return redirect(dest)
