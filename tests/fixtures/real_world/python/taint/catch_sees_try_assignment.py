import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/clean")
def clean():
    path = "/tmp/default"
    if request.args.get("verbose"):
        print("verbose")
    try:
        path = request.args.get("path")
        validate(path)
    except Exception:
        os.system("rm -rf " + path)
    return "done"


@app.route("/fixed")
def fixed():
    path = "/tmp/default"
    if request.args.get("verbose"):
        print("verbose")
    try:
        path = "/tmp/other"
        validate(path)
    except Exception:
        os.system("rm -rf " + path)
    return "done"
