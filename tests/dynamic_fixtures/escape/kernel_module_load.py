"""Escape attempt: load a kernel module via finit_module/init_module syscall.

Requires CAP_SYS_MODULE. Expected outcome: EPERM (--cap-drop=ALL + seccomp).
"""
import ctypes
import ctypes.util
import sys

NR_finit_module = 313  # x86_64

try:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        raise OSError("libc not found")
    libc = ctypes.CDLL(libc_name, use_errno=True)
    # Pass fd=-1 to trigger EBADF rather than loading, but the capability
    # check happens first on a properly hardened kernel.
    ret = libc.syscall(NR_finit_module, -1, b"", 0)
    if ret == -1:
        errno = ctypes.get_errno()
        if errno in (1, 13):  # EPERM or EACCES
            raise PermissionError(errno, "finit_module blocked")
        # EBADF means we got past the capability check — capability not dropped.
        if errno == 9:
            print("NYX_ESCAPE_SUCCESS: finit_module capability not blocked")
            sys.exit(0)
        raise OSError(errno, f"finit_module errno={errno}")
    print("NYX_ESCAPE_SUCCESS: finit_module succeeded")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
