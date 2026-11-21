import subprocess

from flask import request


def disk_usage():
    path = request.args.get("path")
    return subprocess.getoutput("du -sh " + path)
