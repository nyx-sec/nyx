"""Phase 21 (Track M.3) — Django Channels WebsocketConsumer vuln fixture.

`ChatConsumer.receive(text_data=None, bytes_data=None)` splices the
inbound frame into a shell command via `os.system`.
"""
import os

_NYX_ADAPTER_MARKER = "from channels.generic.websocket import WebsocketConsumer"


class ChatConsumer:
    def receive(self, text_data=None, bytes_data=None):
        payload = text_data if text_data is not None else (bytes_data or b"").decode("utf-8", "replace")
        # SINK: tainted frame body concatenated into shell command.
        os.system("echo " + str(payload))


# Module-level alias for the harness to resolve `receive` directly.
def receive(text_data=None, bytes_data=None):
    return ChatConsumer().receive(text_data, bytes_data)
