"""Phase 12 — pytest shape, benign."""
import os
import re
import subprocess

_VALID_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def test_run_ping():
    host = os.environ.get("NYX_PAYLOAD", "")
    if not _VALID_HOST.fullmatch(host):
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
