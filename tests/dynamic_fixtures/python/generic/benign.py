"""Phase 12 — generic shape, benign.

Validates the input against a strict allow-list (alphanumerics + dots
only — RFC-1035 hostname character set) and refuses to shell out when
the input contains anything outside the allow-list.  The CMDI marker
substring (`NYX_PWN_CMDI`) never reaches stdout because the function
returns before any subprocess call when the validation fails.
"""
import re
import subprocess

_VALID_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def run_ping(host):
    """Safe: allow-list validation; refuse and return on mismatch."""
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
