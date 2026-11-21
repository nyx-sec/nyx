import os
import shlex
from flask import Flask, request

app = Flask(__name__)


@app.route("/echo")
def echo():
    msg = request.args.get("msg")
    shown = msg
    shown = shlex.quote(shown)
    print(shown)
    os.system("echo " + msg)
    return "ok"
