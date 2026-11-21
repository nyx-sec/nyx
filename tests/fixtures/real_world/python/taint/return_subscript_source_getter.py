import os
from flask import Flask, request

app = Flask(__name__)


def requested_dir():
    return request.args["dir"]


def configured_cmd():
    return os.environ["CMD"]


def fixed_dir():
    return "/srv/static"


@app.route("/ls")
def ls():
    target = requested_dir()
    os.system("ls " + target)
    return "ok"


@app.route("/cmd")
def cmd():
    c = configured_cmd()
    os.system(c)
    return "ok"


@app.route("/fixed")
def fixed():
    target = fixed_dir()
    os.system("ls " + target)
    return "ok"
