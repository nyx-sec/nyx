# py-safe-canonicalise-rooted-sep: os.path.realpath + .startswith against a
# root constant that ends with a separator.  "/srv/uploads-old/x" no longer
# matches, so the prefix test is a real containment check.
import os
from flask import Flask, request

UPLOAD_ROOT = "/srv/uploads/"
app = Flask(__name__)


@app.route("/file")
def file():
    name = request.args.get("name", "")
    target = os.path.realpath(os.path.join(UPLOAD_ROOT, name))
    if not target.startswith(UPLOAD_ROOT):
        return "forbidden", 403
    with open(target) as f:
        return f.read()
