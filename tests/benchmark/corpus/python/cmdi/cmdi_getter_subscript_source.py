import os
from flask import Flask, request

app = Flask(__name__)


def requested_dir():
    return request.args["dir"]


@app.route("/ls")
def ls():
    target = requested_dir()
    os.system("ls " + target)
    return "ok"
