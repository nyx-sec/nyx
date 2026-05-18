"""Phase 12 (Track L.10) — Flask CMDI vuln fixture.

The `/run` route forwards a `cmd` query parameter straight into
`os.system`, so any attacker who reaches the route can execute
arbitrary shell.  Adapter binding: `@app.route("/run", methods=["GET"])`
with `cmd` flowing through `request.args.get`.
"""
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/run", methods=["GET"])
def run_cmd():
    cmd = request.args.get("cmd", "")
    os.system(cmd)
    return "ok"
