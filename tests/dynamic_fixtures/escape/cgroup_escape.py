"""Escape attempt: write to cgroup hierarchy to escape resource limits.

Requires CAP_SYS_ADMIN. Expected outcome: PermissionError.
"""
import os
import sys

CGROUP_PROCS = "/sys/fs/cgroup/cgroup.procs"
CGROUP_V1 = "/sys/fs/cgroup/memory/cgroup.procs"

target = CGROUP_PROCS if os.path.exists(CGROUP_PROCS) else CGROUP_V1

try:
    with open(target, "w") as f:
        f.write(str(os.getpid()))
    print(f"NYX_ESCAPE_SUCCESS: wrote pid to {target}")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
