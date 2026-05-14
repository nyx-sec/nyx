"""Phase 12 — Flask route, vulnerable.

Vulnerable route reads the `host` query parameter and concatenates it
into a shell command.  Nyx harness reaches the route via
`app.test_client()` so no real network listener is bound.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping", methods=["GET"])
def ping():
    """Vulnerable: untrusted query param flows to subprocess(shell=True)."""
    host = request.args.get("host", "")
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout + result.stderr
