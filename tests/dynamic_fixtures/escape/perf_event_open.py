"""Escape attempt: use perf_event_open to observe host kernel events.

Requires CAP_PERFMON or CAP_SYS_ADMIN. Expected outcome: EPERM.
"""
import ctypes
import ctypes.util
import sys

NR_perf_event_open = 298  # x86_64

try:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        raise OSError("libc not found")
    libc = ctypes.CDLL(libc_name, use_errno=True)

    # Minimal perf_event_attr: type=PERF_TYPE_SOFTWARE, size=120
    buf = (ctypes.c_uint8 * 120)()
    ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0] = 1   # type = PERF_TYPE_SOFTWARE
    ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[2] = 120  # size

    ret = libc.syscall(NR_perf_event_open, buf, -1, -1, -1, 0)
    if ret == -1:
        errno = ctypes.get_errno()
        if errno in (1, 13):  # EPERM / EACCES
            raise PermissionError(errno, "perf_event_open blocked")
        raise OSError(errno, f"perf_event_open errno={errno}")
    libc.close(ret)
    print("NYX_ESCAPE_SUCCESS: perf_event_open succeeded")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
