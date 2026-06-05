"""Phase 21 (Track M.3) — Celery scheduled-task vuln fixture.

`tick(payload)` is a Celery task that splices the payload bytes into a
shell command via `os.system`.  An attacker who can enqueue a task with
arbitrary bytes can inject shell metacharacters.
"""
import os

_NYX_ADAPTER_MARKER = "from celery import shared_task"
_NYX_DECORATOR_MARKER = "@shared_task"


def tick(payload):
    # SINK: tainted payload concatenated into shell command.
    os.system("echo " + str(payload))
