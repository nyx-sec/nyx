"""Phase 12 (Track L.10) — Flask CMDI benign fixture.

The `/run` route accepts a `cmd` query parameter but rejects everything
outside an allowlist before invoking `subprocess.run` with a fixed argv,
so the sink call is unreachable for attacker-controlled values.
"""
import subprocess
from flask import Flask, request

app = Flask(__name__)

_ALLOW = {"status", "uptime", "version"}


@app.route("/run", methods=["GET"])
def run_cmd():
    cmd = request.args.get("cmd", "")
    if cmd not in _ALLOW:
        return "rejected", 400
    subprocess.run(["/usr/bin/echo", cmd], check=False)
    return "ok"
