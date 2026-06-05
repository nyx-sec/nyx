"""Phase 20 (Track M.2) — RabbitMQ Python benign control."""
import os
import shlex

_NYX_ADAPTER_MARKER = "import pika"
_NYX_QUEUE_MARKER = 'queue="work"'


def on_message(ch, method, properties, body):
    if isinstance(body, (bytes, bytearray)):
        body = body.decode('utf-8', 'replace')
    os.system("echo " + shlex.quote(body))
