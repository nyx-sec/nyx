# py-path-traversal-startswith-eq-false: the sink sits inside the branch where
# the prefix test is false, so the path is outside the root.  Comparing the
# test against False must not be read as a containment check.
import os
from flask import Flask, request

ROOT = "/srv/files/"
app = Flask(__name__)


@app.route("/file")
def file():
    name = request.args.get("name", "")
    target = os.path.realpath(os.path.join(ROOT, name))
    if target.startswith(ROOT) is False:
        with open(target) as f:
            return f.read()
    return "ok"
