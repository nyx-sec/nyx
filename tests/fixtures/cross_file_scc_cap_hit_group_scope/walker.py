import os

from flask import request


def walk(node, depth):
    # Self-recursive, so this file runs in the same fixed-point batch as
    # the step_* cycle, but it shares no SCC with it.
    if depth > 3:
        return node
    return walk(node, depth + 1)


def run_tool():
    cmd = request.args.get("tool")
    os.system(cmd)
