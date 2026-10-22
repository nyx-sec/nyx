import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    match request.args.get("cmd"):
        case str(cmd):
            os.system(cmd)
    return "ok"
