"""Phase 20 (Track M.2) — Kafka Python benign control."""
import os
import shlex

_NYX_ADAPTER_MARKER = "from kafka import KafkaConsumer"


def handler(message):
    os.system("echo " + shlex.quote(str(message)))
