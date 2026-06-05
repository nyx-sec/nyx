"""Escape attempt: read /proc/kallsyms to obtain kernel symbol addresses for KASLR bypass.

Expected outcome: empty file or EPERM (unprivileged access returns zeros since Linux 4.15).
"""
import sys

try:
    with open("/proc/kallsyms", "r") as f:
        first_line = f.readline().strip()

    if not first_line:
        print("BLOCKED: /proc/kallsyms is empty (expected)", file=sys.stderr)
        sys.exit(1)

    parts = first_line.split()
    if parts and parts[0] != "0000000000000000":
        print(f"NYX_ESCAPE_SUCCESS: real kernel addresses visible: {parts[0]}")
        sys.exit(0)

    print("BLOCKED: /proc/kallsyms shows zeroed addresses (kptr_restrict active)",
          file=sys.stderr)
    sys.exit(1)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
