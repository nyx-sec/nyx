import subprocess

from flask import request


def disk_usage():
    path = request.args.get("path")
    return subprocess.getoutput("du -sh " + path)


def disk_status():
    path = request.args.get("path")
    return subprocess.getstatusoutput("du -sh " + path)
