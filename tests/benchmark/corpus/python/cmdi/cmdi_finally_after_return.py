# Both the try body and the handler return; the finally clause still runs.
import os

from flask import request


def cleanup():
    target = request.args.get("dir")
    try:
        return "ok"
    except OSError:
        return "failed"
    finally:
        os.system("rm -rf " + target)
