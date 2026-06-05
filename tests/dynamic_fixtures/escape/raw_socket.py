"""Escape attempt: create a raw (AF_PACKET) socket.

Requires CAP_NET_RAW. Expected outcome: PermissionError (--cap-drop=ALL).
"""
import socket
import sys

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.close()
    print("NYX_ESCAPE_SUCCESS: created raw socket")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
