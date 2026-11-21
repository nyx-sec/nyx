import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    # Every payload is already a str.
    if not isinstance(cmd, str):
        return "bad", 400
    os.system(cmd)
    return "ok"
