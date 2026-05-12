"""Escape attempt: create a System V shared memory segment accessible host-wide.

Expected outcome: success creates IPC segment inside the container IPC namespace
(isolated by --ipc private default); OR EPERM if IPC syscalls are blocked.
"""
import sys

try:
    import sysv_ipc
    key = sysv_ipc.ftok("/tmp", ord('N'))
    shm = sysv_ipc.SharedMemory(key, sysv_ipc.IPC_CREAT, size=4096)
    shm.write(b"NYX_IPC_ESCAPE_TEST" + b"\x00" * (4096 - 20))
    # If we can create IPC, check if it's in an isolated namespace.
    # A properly isolated container won't share this with the host.
    # We can only verify this from the host side, so just report success.
    shm.detach()
    shm.remove()
    # IPC created successfully but inside the container namespace — not an escape.
    print("BLOCKED: IPC shm created but confined to container IPC namespace",
          file=sys.stderr)
    sys.exit(1)
except ImportError:
    # sysv_ipc not available — not an escape.
    print("BLOCKED: sysv_ipc module not available", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
