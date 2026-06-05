"""Phase 20 (Track M.2) — RabbitMQ Python vuln fixture.

`on_message` is a `pika.BlockingConnection.channel.basic_consume`
callback whose body argument flows into a shell command.

Adapter marker kept as a string literal so the pika dep is not
required to load the module.
"""
import os

_NYX_ADAPTER_MARKER = "import pika"
_NYX_QUEUE_MARKER = 'queue="work"'


def on_message(ch, method, properties, body):
    if isinstance(body, (bytes, bytearray)):
        body = body.decode('utf-8', 'replace')
    # SINK: tainted body concatenated into shell command
    os.system("echo " + body)
