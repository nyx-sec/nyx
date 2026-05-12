"""Escape attempt: trigger kernel SysRq action via /proc/sysrq-trigger.

Expected outcome: PermissionError (read-only rootfs or missing CAP_SYS_ADMIN).
"""
import sys

try:
    with open("/proc/sysrq-trigger", "w") as f:
        f.write("h")  # 'h' = print help (harmless but requires access)
    print("NYX_ESCAPE_SUCCESS: wrote to /proc/sysrq-trigger")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
