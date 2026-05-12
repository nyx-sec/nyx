"""Escape attempt: use keyctl to read host kernel keyring entries.

Expected outcome: EPERM from seccomp (keyctl is often denied in docker).
"""
import ctypes
import ctypes.util
import sys

NR_keyctl = 250  # x86_64
KEYCTL_SEARCH = 10

try:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        raise OSError("libc not found")
    libc = ctypes.CDLL(libc_name, use_errno=True)
    # KEY_SPEC_USER_KEYRING = -4
    ret = libc.syscall(NR_keyctl, KEYCTL_SEARCH, -4, b"user", b"nyx_test_key", 0)
    if ret == -1:
        errno = ctypes.get_errno()
        if errno in (1, 13, 38):  # EPERM, EACCES, ENOSYS
            raise PermissionError(errno, f"keyctl blocked errno={errno}")
        # ENOKEY (126) = not found but syscall allowed — partial escape
        if errno == 126:
            print("NYX_ESCAPE_SUCCESS: keyctl syscall allowed (key not found but accessible)")
            sys.exit(0)
        raise OSError(errno, f"keyctl errno={errno}")
    print(f"NYX_ESCAPE_SUCCESS: keyctl returned {ret}")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
