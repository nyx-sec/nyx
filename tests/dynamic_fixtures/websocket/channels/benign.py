"""Phase 21 — Django Channels benign control."""
import os
import shlex

_NYX_ADAPTER_MARKER = "from channels.generic.websocket import WebsocketConsumer"


class ChatConsumer:
    def receive(self, text_data=None, bytes_data=None):
        payload = text_data if text_data is not None else (bytes_data or b"").decode("utf-8", "replace")
        os.system("echo " + shlex.quote(str(payload)))


def receive(text_data=None, bytes_data=None):
    return ChatConsumer().receive(text_data, bytes_data)
