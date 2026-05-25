"""Phase 21 — Celery scheduled-task benign control."""
_NYX_ADAPTER_MARKER = "from celery import shared_task"


def tick(payload):
    _ = payload
    return "accepted"
