"""Phase 21 — python-socketio benign control."""
import os
import shlex

_NYX_ADAPTER_MARKER = "import socketio"


def message(sid, data):
    os.system("echo " + shlex.quote(str(data)))
