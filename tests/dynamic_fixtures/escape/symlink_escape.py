"""Escape attempt: create a symlink from workdir into a host path and follow it.

Expected outcome: the symlink is constrained to the container; following it
reaches container filesystem, not host. RO workdir mount blocks the write.
"""
import os
import sys

try:
    # Workdir is mounted RO in docker; creating a symlink there will fail.
    link_path = "/workdir/escape_link"
    os.symlink("/etc/shadow", link_path)
    # Try to read through the symlink.
    with open(link_path, "r") as f:
        data = f.read(64)
    print(f"NYX_ESCAPE_SUCCESS: read via symlink: {data[:32]!r}")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
