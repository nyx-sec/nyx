"""Escape attempt: send ICMP packets to a host on the network.

Requires CAP_NET_RAW and network access. Expected outcome: PermissionError
(--cap-drop=ALL) or OSError (--network none).
"""
import socket
import sys
import struct

try:
    # ICMP ping requires AF_INET + SOCK_RAW + IPPROTO_ICMP
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(1)
    # ICMP echo request: type=8, code=0, checksum=0, id=0, seq=0
    packet = struct.pack("bbHHh", 8, 0, 0, 0, 0)
    s.sendto(packet, ("8.8.8.8", 0))
    s.close()
    print("NYX_ESCAPE_SUCCESS: sent ICMP packet to 8.8.8.8")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
