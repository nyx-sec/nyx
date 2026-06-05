"""Phase 20 (Track M.2) — Google Pub/Sub Python benign control."""
import os
import shlex

_NYX_ADAPTER_MARKER = "from google.cloud import pubsub_v1"
_NYX_TOPIC_MARKER = '.subscribe("projects/p/subscriptions/s"'


def callback(message):
    body = getattr(message, 'data', None)
    if body is None and isinstance(message, dict):
        body = message.get('data')
    if isinstance(body, (bytes, bytearray)):
        body = body.decode('utf-8', 'replace')
    if body is None:
        body = str(message)
    os.system("echo " + shlex.quote(body))
    try:
        message.ack()
    except Exception:
        pass
