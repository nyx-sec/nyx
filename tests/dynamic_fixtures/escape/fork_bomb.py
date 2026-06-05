"""Escape attempt: fork bomb to exhaust host process table.

Expected outcome: killed by PID limit (pids-limit in docker) or timeout.
"""
import os
import sys

try:
    # Attempt a fork bomb; limited by docker --pids-limit or sandbox timeout.
    pids = []
    for _ in range(512):
        pid = os.fork()
        if pid == 0:
            # Child: loop forever
            while True:
                pass
        pids.append(pid)
    # Should not reach here in a properly sandboxed environment.
    print("NYX_ESCAPE_SUCCESS: fork bomb created 512 children")
    sys.exit(0)
except (BlockingIOError, PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
