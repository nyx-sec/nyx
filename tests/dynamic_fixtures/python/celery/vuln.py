"""Phase 12 — Celery task, vulnerable.

Celery's `@app.task` decorator wraps the underlying function on a Task
object.  Nyx harness reaches the inner callable via `.run` /
`.__wrapped__` so no broker is required.
"""
import subprocess

from celery import Celery

app = Celery("nyx_fixture")


@app.task
def run_job(host):
    """Vulnerable Celery task body."""
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
    print(result.stderr, end="")
