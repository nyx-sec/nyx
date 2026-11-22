import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name")
    clean = os.path.normpath(name)
    # A normalized path holds `..` only at the start, so rejecting a leading
    # `..` and an absolute path leaves a relative path under BASE.
    if clean.startswith("..") or clean.startswith("/"):
        abort(400)
    return send_file(os.path.join(BASE, clean))
