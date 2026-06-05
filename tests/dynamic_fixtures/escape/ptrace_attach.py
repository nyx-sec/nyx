"""Escape attempt: ptrace PID 1 (init/systemd on host).

Requires CAP_SYS_PTRACE. Expected outcome: EPERM (--cap-drop=ALL + seccomp).
"""
import ctypes
import ctypes.util
import sys

PTRACE_ATTACH = 16

try:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        raise OSError("libc not found")
    libc = ctypes.CDLL(libc_name, use_errno=True)
    ret = libc.ptrace(PTRACE_ATTACH, 1, 0, 0)
    if ret == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ptrace EPERM errno={errno}")
    print("NYX_ESCAPE_SUCCESS: ptrace attached to pid 1")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
