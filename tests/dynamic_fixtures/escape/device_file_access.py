"""Escape attempt: open /dev/mem to read physical memory.

Requires CAP_SYS_RAWIO (and typically root). With --cap-drop=ALL and
--user 65534:65534, both privilege escalation (setuid) and device access
are blocked by distinct kernel checks, exercising two security layers.
"""
import os
import sys

# Attempt privilege escalation first (tests CAP_SETUID independently).
# With --cap-drop=ALL, setuid(0) requires CAP_SETUID — also dropped.
if os.getuid() != 0:
    try:
        os.setuid(0)
    except (PermissionError, OSError) as e:
        print(f"BLOCKED (setuid): {e}", file=sys.stderr)
        # Fall through: also probe /dev/mem directly to test CAP_SYS_RAWIO.

try:
    with open("/dev/mem", "rb") as f:
        data = f.read(64)
    print(f"NYX_ESCAPE_SUCCESS: read {len(data)} bytes from /dev/mem")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: {e}", file=sys.stderr)
    sys.exit(1)
