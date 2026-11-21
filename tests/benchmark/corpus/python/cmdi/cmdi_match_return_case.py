import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    match request.args.get("mode"):
        case "quit":
            return "bye"
        case _:
            os.system(cmd)
    return "ok"
