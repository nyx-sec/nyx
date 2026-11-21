import html
import os
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/escaped")
def escaped():
    # Vulnerable: html.escape leaves shell syntax alone.  The nested
    # sanitizer call must not hide the Popen sink around it.
    name = request.args.get("name")
    subprocess.Popen(["sh", "-c", html.escape(name)])
    return "ok"


@app.route("/leaf")
def leaf():
    # Vulnerable: basename drops directories, not shell syntax.
    name = request.args.get("name")
    subprocess.Popen(["sh", "-c", os.path.basename(name)])
    return "ok"


@app.route("/quoted")
def quoted():
    # Safe: shlex.quote makes the value a single shell word.
    name = request.args.get("name")
    subprocess.Popen(["sh", "-c", "ls " + shlex.quote(name)])
    return "ok"
