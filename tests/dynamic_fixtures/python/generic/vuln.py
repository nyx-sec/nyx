"""Phase 12 — generic shape, vulnerable.

Module-level function that shells out with user input directly
concatenated.  Mirrors `cmdi_positive.py` but lives under the per-shape
fixture tree so the shape detector hits the `Generic` path.
"""
import subprocess


def run_ping(host):
    """Vulnerable: user input concatenated into shell command."""
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
    print(result.stderr, end="")
