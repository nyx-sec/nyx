"""Phase 21 — Celery scheduled-task benign control."""
import os
import shlex

_NYX_ADAPTER_MARKER = "from celery import shared_task"


def tick(payload):
    os.system("echo " + shlex.quote(str(payload)))
