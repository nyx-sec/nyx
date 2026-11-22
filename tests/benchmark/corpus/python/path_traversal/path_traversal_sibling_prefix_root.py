# py-path-traversal-sibling-prefix: os.path.realpath + .startswith against a
# root constant that ends without a separator.  "/srv/uploads-old/x" starts
# with "/srv/uploads", so the guard admits a sibling directory and the sink is
# reached by a path outside the upload directory.
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
