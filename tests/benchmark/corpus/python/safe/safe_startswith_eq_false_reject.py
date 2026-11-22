# py-safe-startswith-eq-false-reject: rejecting on `startswith(ROOT) == False`
# leaves only paths inside the root for the sink.
import os
from flask import Flask, request

ROOT = "/srv/files/"
app = Flask(__name__)


@app.route("/file")
def file():
    name = request.args.get("name", "")
    target = os.path.realpath(os.path.join(ROOT, name))
    if target.startswith(ROOT) == False:  # noqa: E712
        return "forbidden", 403
    with open(target) as f:
        return f.read()
