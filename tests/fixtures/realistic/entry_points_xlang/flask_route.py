# Phase 16 fixture: Flask route handler.  The `@app.route(...)` decorator
# with `methods=["POST"]` marks `submit` as a `FlaskRoute { method: POST }`
# entry point.  The path-captured `name` formal is auto-seeded as
# `Source(Cap::all())` and forwarded into `os.system`, firing
# SHELL_ESCAPE.
from flask import Flask
import os

app = Flask(__name__)


@app.route("/submit/<name>", methods=["POST"])
def submit(name):
    os.system("echo " + name)
    return "ok"
