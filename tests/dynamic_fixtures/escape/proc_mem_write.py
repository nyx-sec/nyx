"""Escape attempt: write to /proc/self/mem to overwrite own memory.

Expected outcome: PermissionError or EPERM from seccomp/kernel.
"""
import os
import sys

try:
    with open("/proc/self/mem", "wb") as f:
        f.seek(0)
        f.write(b"\x00" * 4096)
    print("NYX_ESCAPE_SUCCESS: wrote to /proc/self/mem")
    sys.exit(0)
except (PermissionError, OSError, IOError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
