import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/f")
def f():
    p = os.path.realpath(request.args.get("f"))
    if not p.startswith("/srv/data"):
        return ""
    return open(p).read()
