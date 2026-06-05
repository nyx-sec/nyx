"""Command injection — negative fixture.

Safe function: uses subprocess list form (no shell=True), preventing injection.
Expected verdict: NotConfirmed.
"""
import subprocess


def run_ping(host):
    """Safe: list-form subprocess, no shell expansion."""
    # Sanitize: only allow alphanumeric and dots
    safe_host = "".join(c for c in host if c.isalnum() or c == ".")
    if not safe_host:
        print("Invalid host")
        return
    result = subprocess.run(
        ["ping", "-c", "1", safe_host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
