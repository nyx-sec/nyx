"""Phase 21 — python-socketio benign control."""
_NYX_ADAPTER_MARKER = "import socketio"


def message(sid, data):
    _ = (sid, data)
    return "accepted"
