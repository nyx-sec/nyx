"""Phase 21 (Track M.3) — python-socketio handler vuln fixture.

`message(sid, data)` is a Socket.IO event handler.  It splices the
inbound message into a shell command via `os.system`.
"""
import os

_NYX_ADAPTER_MARKER = "import socketio"
_NYX_EVENT_MARKER = "@sio.on('message')"


def message(sid, data):
    # SINK: tainted message body concatenated into shell command.
    os.system("echo " + str(data))
