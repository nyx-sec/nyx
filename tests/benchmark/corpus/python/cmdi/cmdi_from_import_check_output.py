from subprocess import check_output

from flask import request


def listing():
    path = request.args.get("path")
    return check_output("ls " + path, shell=True)
