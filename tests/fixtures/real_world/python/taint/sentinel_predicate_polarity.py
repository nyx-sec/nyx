import os
from flask import Flask, request

app = Flask(__name__)


def is_valid_name(s):
    return s.isalnum()


@app.route("/a")
def safe_eq_false():
    name = request.args.get("name")
    if is_valid_name(name) == False:
        return "bad", 400
    os.system("echo " + name)
    return "ok"


@app.route("/b")
def safe_is_false():
    name = request.args.get("name")
    if is_valid_name(name) is False:
        return "bad", 400
    os.system("echo " + name)
    return "ok"


@app.route("/c")
def vuln_eq_false():
    name = request.args.get("name")
    if is_valid_name(name) == False:
        os.system("echo " + name)
    return "ok"


@app.route("/d")
def safe_indirect_not():
    cmd = request.args.get("cmd")
    ok = is_valid_command(cmd)
    if not ok:
        return "bad", 400
    os.system(cmd)
    return "ok"


@app.route("/e")
def vuln_indirect_not():
    cmd = request.args.get("cmd")
    ok = is_valid_command(cmd)
    if not ok:
        os.system(cmd)
    return "ok"
