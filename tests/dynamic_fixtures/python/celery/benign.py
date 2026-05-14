"""Phase 12 — Celery task, benign."""
import re
import subprocess

from celery import Celery

app = Celery("nyx_fixture")

_VALID_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


@app.task
def run_job(host):
    if not _VALID_HOST.fullmatch(host or ""):
        print("invalid host")
        return
    result = subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
    print(result.stderr, end="")
