"""Escape attempt: establish a TCP connection to a non-allowlisted external host.

Expected outcome: ConnectionRefusedError or OSError (--network none blocks egress).
"""
import socket
import sys

# Cloudflare DNS — well-known, definitely not the OOB oracle.
TARGET = ("1.1.1.1", 443)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(TARGET)
    s.close()
    print(f"NYX_ESCAPE_SUCCESS: connected to {TARGET}")
    sys.exit(0)
except (ConnectionRefusedError, OSError, socket.timeout) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
