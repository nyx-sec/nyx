"""Phase 12 (Track L.10) — FastAPI CMDI benign fixture.

`GET /run?cmd=<...>` rejects anything outside an allowlist before
invoking `subprocess.run` with a fixed argv, so the sink call is
unreachable for attacker-controlled values.
"""
import subprocess
from fastapi import FastAPI

app = FastAPI()

_ALLOW = {"status", "uptime", "version"}


@app.get("/run")
def run_cmd(cmd: str = ""):
    if cmd not in _ALLOW:
        return {"rejected": True}
    subprocess.run(["/usr/bin/echo", cmd], check=False)
    return {"ok": True}
