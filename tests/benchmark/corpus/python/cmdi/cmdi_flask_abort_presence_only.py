import subprocess
from flask import Flask, request, abort

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    if not cmd:
        abort(400)
    return subprocess.check_output(cmd, shell=True)
