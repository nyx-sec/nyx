"""Escape attempt: detect host-only env variables leaking into the sandbox.

Docker base images set HOME/PATH/LANG themselves, so those alone are not a
host leak. We probe for variables that only exist on a developer host:
USER/LOGNAME/SHELL (set by login shells) and SSH_*/XDG_* (set by the
developer's session). Exit 0 only when one of those host-only markers is
present in the sandbox env.
"""
import os
import sys

host_only = ["USER", "LOGNAME", "SHELL", "SSH_CONNECTION", "SSH_TTY", "XDG_SESSION_ID"]
leaked = [k for k in host_only if k in os.environ]

if leaked:
    print(f"NYX_ESCAPE_SUCCESS: host env vars leaked: {leaked}")
    sys.exit(0)

visible = list(os.environ.keys())[:5]
print(f"BLOCKED: host-only env vars absent; visible sample: {visible}",
      file=sys.stderr)
sys.exit(1)
