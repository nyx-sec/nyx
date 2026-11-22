"""Containment by string prefix: the root must end with a separator."""
import os
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)

BARE_ROOT = "/srv/files"
DIR_ROOT = "/srv/files/"
ABS_ROOT = os.path.abspath("/srv/files")


@app.route("/bare-const")
def bare_const():
    p = os.path.realpath(request.args.get("f"))
    if not p.startswith(BARE_ROOT):
        return "forbidden", 403
    return open(p).read()  # @vuln sibling directory shares the prefix


@app.route("/bare-literal")
def bare_literal():
    p = os.path.realpath(request.args.get("f"))
    if not p.startswith("/srv/files"):
        return "forbidden", 403
    return open(p).read()  # @vuln sibling directory shares the prefix


@app.route("/abspath-root")
def abspath_root():
    p = os.path.realpath(request.args.get("f"))
    if not p.startswith(ABS_ROOT):
        return "forbidden", 403
    return open(p).read()  # @vuln abspath drops the trailing separator


@app.route("/dir-const")
def dir_const():
    p = os.path.realpath(request.args.get("f"))
    if not p.startswith(DIR_ROOT):
        return "forbidden", 403
    return open(p).read()  # @safe root ends with a separator


@app.route("/dir-literal")
def dir_literal():
    p = os.path.realpath(request.args.get("f"))
    if not p.startswith("/srv/files/"):
        return "forbidden", 403
    return open(p).read()  # @safe root ends with a separator


@app.route("/sep-joined")
def sep_joined():
    p = os.path.realpath(request.args.get("f"))
    if not p.startswith(BARE_ROOT + os.sep):
        return "forbidden", 403
    return open(p).read()  # @safe separator appended at the test


@app.route("/relative-to")
def relative_to():
    p = Path(os.path.realpath(request.args.get("f")))
    if not p.is_relative_to(BARE_ROOT):
        return "forbidden", 403
    return open(p).read()  # @safe compares path components
