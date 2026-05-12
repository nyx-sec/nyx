"""Escape attempt: write a file outside the sandboxed workdir.

Expected outcome: PermissionError or write succeeds but test checks host.
Exit 0 only when escape succeeds (file written outside container).
"""
import os
import sys

marker = "/tmp/nyx_escape_file_write_marker"
try:
    with open(marker, "w") as f:
        f.write("NYX_ESCAPE_SUCCESS")
    print("NYX_ESCAPE_SUCCESS: wrote to host /tmp")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
