"""Escape attempt: unshare PID namespace to hide from host ps.

Requires CAP_SYS_ADMIN. Expected outcome: EPERM.
"""
import ctypes
import ctypes.util
import sys

CLONE_NEWPID = 0x20000000

try:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        raise OSError("libc not found")
    libc = ctypes.CDLL(libc_name, use_errno=True)
    ret = libc.unshare(CLONE_NEWPID)
    if ret == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, f"unshare(CLONE_NEWPID) blocked errno={errno}")
    print("NYX_ESCAPE_SUCCESS: created new PID namespace")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
