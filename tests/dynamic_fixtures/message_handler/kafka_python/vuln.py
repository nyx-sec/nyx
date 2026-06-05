"""Phase 20 (Track M.2) — Kafka Python vuln fixture.

`handler` is a Kafka consumer callback (modelled after
`KafkaConsumer('orders').poll()` dispatch) that splices the raw
message body into a shell command via `os.system`.  A malicious
producer can inject command-separator metacharacters into the body
and the shell will execute them — the classic message-handler cmdi
shape.

Adapter source-marker: `from kafka import KafkaConsumer` is kept as a
docstring reference (not a top-level import) so the harness can run
without the real `kafka-python` library installed on the host.
"""
import os

# Phase 20 framework adapter detects this fixture via the `from kafka`
# / `import kafka` substring scan.  Keeping the marker in source lets
# the adapter bind without forcing the host to pin the kafka-python
# pip dep just to load the fixture module.
_NYX_ADAPTER_MARKER = "from kafka import KafkaConsumer"


def handler(message):
    # SINK: tainted message body concatenated into shell command
    os.system("echo " + str(message))
