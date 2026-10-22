import os
import shlex
from flask import Flask, request

app = Flask(__name__)


@app.route("/ls")
def ls():
    path = request.args.get("path")
    opts = request.args.get("opts")
    os.system("ls " + shlex.quote(path) + " " + opts)
    return "ok"
