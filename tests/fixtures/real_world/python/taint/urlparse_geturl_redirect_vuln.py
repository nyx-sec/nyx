from urllib.parse import urlparse

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("next", "/")
    parsed = urlparse(target)
    # geturl() rebuilds the full URL, scheme and host included.
    dest = parsed.geturl()
    return redirect(dest)
