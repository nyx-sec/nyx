"""Phase 20 (Track M.2) — SQS Python benign control."""
import os
import shlex

_NYX_ADAPTER_MARKER = "boto3.client('sqs')"


def handler(envelope):
    body = envelope.get('Body', '') if isinstance(envelope, dict) else str(envelope)
    os.system("echo " + shlex.quote(body))
