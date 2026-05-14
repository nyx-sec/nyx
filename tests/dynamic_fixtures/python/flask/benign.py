"""Phase 12 — Flask route, benign."""
import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

_VALID_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


@app.route("/ping", methods=["GET"])
def ping():
    host = request.args.get("host", "")
    if not _VALID_HOST.fullmatch(host):
        return "invalid host"
    result = subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout + result.stderr
