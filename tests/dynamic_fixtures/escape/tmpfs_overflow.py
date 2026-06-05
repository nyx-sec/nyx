"""Escape attempt: exhaust host disk/tmpfs by writing large files.

Expected outcome: ENOSPC or killed by cgroup memory limit.
"""
import sys
import os

CHUNK = 1024 * 1024  # 1 MiB
MAX_WRITES = 8192    # 8 GiB total — well above any reasonable tmpfs limit

try:
    written = 0
    files = []
    for i in range(MAX_WRITES):
        path = f"/tmp/nyx_overflow_{i}"
        files.append(path)
        with open(path, "wb") as f:
            f.write(b"\x00" * CHUNK)
        written += CHUNK
    print(f"NYX_ESCAPE_SUCCESS: wrote {written // (1024*1024)} MiB to /tmp")
    sys.exit(0)
except (OSError, IOError) as e:
    # ENOSPC expected — disk/tmpfs is full, no host impact.
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
finally:
    # Cleanup: don't leave huge files even on partial success.
    for p in files:
        try:
            os.unlink(p)
        except OSError:
            pass
