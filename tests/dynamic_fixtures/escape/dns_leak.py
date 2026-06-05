"""Escape attempt: perform a DNS lookup to leak container identity.

Expected outcome: socket.gaierror (--network none, no DNS resolver).
"""
import socket
import sys

try:
    # Try to resolve an external hostname; requires network access.
    ip = socket.gethostbyname("google.com")
    print(f"NYX_ESCAPE_SUCCESS: DNS resolved google.com -> {ip}")
    sys.exit(0)
except (socket.gaierror, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
