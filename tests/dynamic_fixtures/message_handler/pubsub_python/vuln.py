"""Phase 20 (Track M.2) — Google Pub/Sub Python vuln fixture.

`callback` is a `pubsub_v1.SubscriberClient.subscribe` callback that
takes `message.data` bytes straight into a shell command.

Adapter marker kept as a string literal so the google-cloud-pubsub dep
is not required to load the module.
"""
import os

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
    # SINK: tainted message body concatenated into shell command
    os.system("echo " + body)
    try:
        message.ack()
    except Exception:
        pass
