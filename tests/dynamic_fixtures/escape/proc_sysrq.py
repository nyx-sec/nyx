"""Escape attempt: trigger kernel SysRq action via /proc/sysrq-trigger.

Requires CAP_SYS_ADMIN (and typically root). With --cap-drop=ALL and
--user 65534:65534, both privilege escalation (setuid) and the sysrq
write are blocked by distinct kernel checks.
"""
import os
import sys

# Attempt privilege escalation first (tests CAP_SETUID independently).
# With --cap-drop=ALL, setuid(0) requires CAP_SETUID — also dropped.
if os.getuid() != 0:
    try:
        os.setuid(0)
    except (PermissionError, OSError) as e:
        print(f"BLOCKED (setuid): {e}", file=sys.stderr)
        # Fall through: also probe /proc/sysrq-trigger to test CAP_SYS_ADMIN.

try:
    with open("/proc/sysrq-trigger", "w") as f:
        f.write("h")  # 'h' = print help (harmless but requires access)
    print("NYX_ESCAPE_SUCCESS: wrote to /proc/sysrq-trigger")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
