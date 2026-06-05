"""Command injection — positive fixture.

Vulnerable function: passes user input directly to shell=True subprocess.
Expected verdict: Confirmed (payload "; echo NYX_PWN_CMDI" echoes the marker).
"""
import subprocess


def run_ping(host):
    """Vulnerable: user input in shell command."""
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
    print(result.stderr, end="")
