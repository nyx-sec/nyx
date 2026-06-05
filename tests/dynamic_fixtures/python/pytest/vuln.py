"""Phase 12 — pytest shape, vulnerable.

Pytest convention: function name starts with `test_`.  Nyx harness
injects the payload via the `NYX_PAYLOAD` env var (the same channel
pytest fixtures typically read from).
"""
import os
import subprocess


def test_run_ping():
    """Vulnerable test: reads host from env, concatenates into shell."""
    host = os.environ.get("NYX_PAYLOAD", "")
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
    print(result.stderr, end="")
