"""Phase 20 (Track M.2) — SQS Python vuln fixture.

`handler` is a boto3 SQS poller callback that takes the raw envelope's
`Body` field straight into a shell command.

Adapter marker kept as a string literal so the boto3 dep is not
required to load the module.
"""
import os

_NYX_ADAPTER_MARKER = "boto3.client('sqs')"


def handler(envelope):
    body = envelope.get('Body', '') if isinstance(envelope, dict) else str(envelope)
    # SINK: tainted Body concatenated into shell command
    os.system("echo " + body)
