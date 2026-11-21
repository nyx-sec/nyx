import subprocess
from flask import Flask, request

app = Flask(__name__)
ALLOWED = {"ls", "pwd"}


def abort(code):
    print("rejected", code)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    if cmd not in ALLOWED:
        abort(400)
    return subprocess.check_output(cmd, shell=True)
