# The handler runs after the try body assigned `path`.
import os

from flask import request


def clean():
    path = "/tmp/default"
    if request.args.get("verbose"):
        print("verbose")
    try:
        path = request.args.get("path")
        validate(path)
    except Exception:
        os.system("rm -rf " + path)
    return "done"
