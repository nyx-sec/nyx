import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/cleanup")
def cleanup():
    target = request.args.get("dir")
    try:
        return "ok"
    except OSError:
        return "failed"
    finally:
        os.system("rm -rf " + target)


@app.route("/rotate")
def rotate():
    request.args.get("dir")
    try:
        return "ok"
    finally:
        subprocess.run(["logrotate", "/etc/app.conf"])
