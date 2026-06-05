"""Escape attempt: bind-mount a host path into the container.

Requires CAP_SYS_ADMIN. Expected outcome: EPERM (--cap-drop=ALL).
"""
import ctypes
import ctypes.util
import sys
import os

MS_BIND = 4096

try:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        raise OSError("libc not found")
    libc = ctypes.CDLL(libc_name, use_errno=True)
    os.makedirs("/tmp/mnt_target", exist_ok=True)
    ret = libc.mount(b"/", b"/tmp/mnt_target", b"none", MS_BIND, 0)
    if ret == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, f"mount failed errno={errno}")
    print("NYX_ESCAPE_SUCCESS: mounted host / into container")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
