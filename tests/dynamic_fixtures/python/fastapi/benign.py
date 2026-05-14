"""Phase 12 — FastAPI route, benign."""
import re
import subprocess

from fastapi import FastAPI

app = FastAPI()

_VALID_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


@app.get("/ping")
def ping(host: str = ""):
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
