"""Escape attempt: create a new user namespace to gain capabilities.

Expected outcome: EPERM (Docker no-new-privileges blocks unshare).
"""
import ctypes
import ctypes.util
import sys

CLONE_NEWUSER = 0x10000000
NR_unshare = 272  # x86_64

try:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        raise OSError("libc not found")
    libc = ctypes.CDLL(libc_name, use_errno=True)
    ret = libc.unshare(CLONE_NEWUSER)
    if ret == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, f"unshare(CLONE_NEWUSER) blocked errno={errno}")
    # If we get here, we're in a new user namespace — check if we're root.
    uid = libc.getuid()
    if uid == 0:
        print("NYX_ESCAPE_SUCCESS: gained root in new user namespace")
        sys.exit(0)
    print(f"PARTIAL: unshare succeeded but uid={uid}", file=sys.stderr)
    sys.exit(1)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
