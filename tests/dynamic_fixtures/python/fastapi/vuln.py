"""Phase 12 — FastAPI route, vulnerable.

Nyx harness drives the route through `starlette.testclient.TestClient`
so the framework's normal request pipeline fires without a real socket.
"""
import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str = ""):
    """Vulnerable: query parameter flows to subprocess(shell=True)."""
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout + result.stderr
