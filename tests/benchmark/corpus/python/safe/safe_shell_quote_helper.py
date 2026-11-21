import os
import shlex
from flask import Flask, request
app = Flask(__name__)

def clean(v):
    return shlex.quote(v)

@app.route("/q")
def q():
    name = request.args.get("name")
    os.system("echo " + clean(name))
    return "ok"
