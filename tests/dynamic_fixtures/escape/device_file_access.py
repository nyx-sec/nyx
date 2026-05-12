"""Escape attempt: open /dev/mem to read physical memory.

Requires CAP_SYS_RAWIO. Expected outcome: PermissionError.
"""
import sys

try:
    with open("/dev/mem", "rb") as f:
        data = f.read(64)
    print(f"NYX_ESCAPE_SUCCESS: read {len(data)} bytes from /dev/mem")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
