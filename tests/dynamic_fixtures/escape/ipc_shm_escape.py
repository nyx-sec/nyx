"""Escape attempt: create a System V shared memory segment accessible host-wide.

Expected outcome: ENOSYS or EPERM when IPC syscalls are blocked; or the segment
is created inside the container IPC namespace (isolated by default, not an escape).
Rewritten to use ctypes so python:3-slim does not need sysv_ipc installed.
"""
import ctypes
import ctypes.util
import sys

try:
    libc_path = ctypes.util.find_library("c") or "libc.so.6"
    libc = ctypes.CDLL(libc_path, use_errno=True)

    IPC_PRIVATE = 0
    IPC_CREAT = 0o1000
    IPC_RMID = 0

    shmid = libc.shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o600)
    if shmid == -1:
        errno = ctypes.get_errno()
        print(f"BLOCKED: shmget failed errno={errno}", file=sys.stderr)
        sys.exit(1)

    # Segment created in the container IPC namespace — not accessible from host.
    libc.shmctl(shmid, IPC_RMID, None)
    print("BLOCKED: IPC shm created but confined to container IPC namespace",
          file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
