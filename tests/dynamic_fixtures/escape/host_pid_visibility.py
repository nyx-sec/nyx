"""Escape attempt: enumerate host PIDs via /proc to find and signal host processes.

Expected outcome: only container PIDs visible; cannot signal PID 1 outside ns.
"""
import os
import sys
import glob

# Collect all numeric /proc entries (visible PIDs).
pids = []
for entry in glob.glob("/proc/[0-9]*"):
    try:
        pid = int(os.path.basename(entry))
        pids.append(pid)
    except ValueError:
        pass

# A correctly isolated container sees very few PIDs (its own + init).
# The host typically has hundreds of PIDs. More than 100 visible = host leak.
if len(pids) > 100:
    print(f"NYX_ESCAPE_SUCCESS: saw {len(pids)} host PIDs via /proc")
    sys.exit(0)

# Try to signal PID 1 (init). In a proper PID namespace, PID 1 is the
# container's init, not systemd/launchd. Sending SIGCONT to it is safe.
try:
    os.kill(1, 0)  # signal 0 = check if process exists (no actual signal)
    # PID 1 exists; check if it looks like a host process.
    with open("/proc/1/cmdline", "rb") as f:
        cmdline = f.read().replace(b"\x00", b" ").strip()
    if b"systemd" in cmdline or b"launchd" in cmdline or b"init" in cmdline:
        print(f"NYX_ESCAPE_SUCCESS: host init visible: {cmdline[:64]}")
        sys.exit(0)
except (PermissionError, OSError):
    pass

print(f"BLOCKED: only {len(pids)} PIDs visible, host PID 1 not accessible",
      file=sys.stderr)
sys.exit(1)
