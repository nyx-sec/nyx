import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/run", methods=["POST"])
def run_all():
    for cmd in request.json["commands"]:
        os.system(cmd)
    return "ok"


@app.route("/fixed")
def run_fixed():
    for cmd in ["uptime", "df"]:
        os.system(cmd)
    return "ok"
