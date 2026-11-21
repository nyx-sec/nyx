# The sink call is the `if` condition itself.
import os

from flask import request


def run():
    cmd = request.args.get("cmd")
    if os.system(cmd):
        return "failed"
    return "ok"
