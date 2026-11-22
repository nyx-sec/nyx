import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/f")
def f():
    name = request.args.get("f", "")
    p = os.path.realpath(os.path.join("/srv/data", name))
    if not p.startswith("/srv/data" + os.sep):
        return ""
    with open(p) as fh:
        return fh.read()
