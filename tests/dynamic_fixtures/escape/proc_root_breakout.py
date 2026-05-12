"""Escape attempt: read host filesystem via /proc/1/root.

In a properly isolated container, /proc/1/root resolves to the container's
own rootfs — same (st_dev, st_ino) as `/`. A breakout would show a
different rootfs (host's), detectable via differing device/inode.

The earlier check `os.path.isdir("/proc/1/root/proc/1/root")` was unsound:
/proc/1/root is a magic symlink to the container's `/`, so the path
re-resolves to a real directory in any container — yielding a false
NYX_ESCAPE_SUCCESS even when no escape occurred.
"""
import os
import sys

try:
    proc_root = os.stat("/proc/1/root")
    own_root = os.stat("/")
    if (proc_root.st_dev, proc_root.st_ino) != (own_root.st_dev, own_root.st_ino):
        print(f"NYX_ESCAPE_SUCCESS: /proc/1/root exposes a different rootfs "
              f"(dev={proc_root.st_dev} ino={proc_root.st_ino} "
              f"vs dev={own_root.st_dev} ino={own_root.st_ino})")
        sys.exit(0)
    print("BLOCKED: /proc/1/root is container's own rootfs (dev/ino match)",
          file=sys.stderr)
    sys.exit(1)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
