# py-safe-canonicalise-rooted: os.path.realpath + .startswith with a
# non-literal root variable (an opaque prefix-lock).  Combined with
# realpath's dotdot=No proof, is_path_traversal_safe should suppress the
# FILE_IO sink even though the canonicalised path is absolute.
import os
from flask import Flask, request

UPLOAD_ROOT = "/srv/uploads"
app = Flask(__name__)


@app.route("/file")
def file():
    name = request.args.get("name", "")
    target = os.path.realpath(os.path.join(UPLOAD_ROOT, name))
    if not target.startswith(UPLOAD_ROOT):
        return "forbidden", 403
    with open(target) as f:
        return f.read()
