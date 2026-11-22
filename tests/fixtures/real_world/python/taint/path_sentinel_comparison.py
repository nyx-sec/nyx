"""A prefix test compared against a boolean sentinel."""
import os

from flask import Flask, request

app = Flask(__name__)

ROOT = "/srv/files/"


@app.route("/eq-false-reject")
def eq_false_reject():
    p = os.path.realpath(request.args.get("f"))
    if p.startswith(ROOT) == False:  # noqa: E712
        return "forbidden", 403
    return open(p).read()  # @safe reached only when the prefix test is true


@app.route("/is-false-reject")
def is_false_reject():
    p = os.path.realpath(request.args.get("f"))
    if p.startswith(ROOT) is False:
        return "forbidden", 403
    return open(p).read()  # @safe reached only when the prefix test is true


@app.route("/ne-true-reject")
def ne_true_reject():
    p = os.path.realpath(request.args.get("f"))
    if p.startswith(ROOT) != True:  # noqa: E712
        return "forbidden", 403
    return open(p).read()  # @safe reached only when the prefix test is true


@app.route("/is-not-true-reject")
def is_not_true_reject():
    p = os.path.realpath(request.args.get("f"))
    if p.startswith(ROOT) is not True:
        return "forbidden", 403
    return open(p).read()  # @safe reached only when the prefix test is true


@app.route("/eq-false-serve")
def eq_false_serve():
    p = os.path.realpath(request.args.get("f"))
    if p.startswith(ROOT) == False:  # noqa: E712
        return open(p).read()  # @vuln the path is outside the root here
    return "ok"


@app.route("/is-false-serve")
def is_false_serve():
    p = os.path.realpath(request.args.get("f"))
    if p.startswith(ROOT) is False:
        return open(p).read()  # @vuln the path is outside the root here
    return "ok"
