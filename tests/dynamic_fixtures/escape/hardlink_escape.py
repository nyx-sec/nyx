"""Escape attempt: create a hardlink to a sensitive file outside the workdir.

Expected outcome: PermissionError (EPERM — cross-device or protected hardlink).
Linux protects hardlinks to files owned by other users since 3.6+.
"""
import os
import sys

try:
    os.link("/etc/shadow", "/tmp/shadow_hardlink")
    with open("/tmp/shadow_hardlink", "r") as f:
        data = f.read(64)
    print(f"NYX_ESCAPE_SUCCESS: hardlinked /etc/shadow: {data[:32]!r}")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
