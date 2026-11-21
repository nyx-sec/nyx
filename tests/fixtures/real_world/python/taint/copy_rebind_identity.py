import os
import shlex
from flask import Flask, request

app = Flask(__name__)


def default_cmd():
    return "ls -la"


@app.route("/rebind")
def rebind():
    cmd = default_cmd()
    user_cmd = cmd
    user_cmd = request.args.get("c")
    print(user_cmd)
    os.system(cmd)
    return "ok"


@app.route("/quoted-copy")
def quoted_copy():
    x = request.args.get("c")
    y = x
    y = shlex.quote(y)
    print(y)
    os.system("echo " + x)
    return "ok"
