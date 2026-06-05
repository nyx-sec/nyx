"""Escape attempt: regain root after dropping privileges.

Docker's python:3-slim base runs as uid 0, so `setuid(0)` from root is a
no-op — that path cannot distinguish a real escape. Instead: drop to
`nobody` (uid 65534), then attempt to regain uid 0. With --cap-drop=ALL
(no CAP_SETUID) plus no-new-privileges, regaining uid 0 must fail.

If we already start as non-root, skip the drop and go straight to the
escalation attempt.
"""
import os
import sys

if os.getuid() == 0:
    try:
        os.setuid(65534)  # nobody
    except OSError as e:
        print(f"INDETERMINATE: cannot drop privileges to nobody: {e}",
              file=sys.stderr)
        sys.exit(1)

try:
    os.setuid(0)
    if os.getuid() == 0:
        print("NYX_ESCAPE_SUCCESS: regained uid 0 after dropping privileges")
        sys.exit(0)
    print(f"PARTIAL: setuid(0) succeeded but uid={os.getuid()}", file=sys.stderr)
    sys.exit(1)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
