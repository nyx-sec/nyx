import os
import shlex
from flask import Flask, request

app = Flask(__name__)


def first(aval, zval):
    return aval


def to_int(s):
    return int(s)


def quote_it(s):
    return shlex.quote(s)


def maybe_quote(value, strict):
    if strict:
        return shlex.quote(value)
    return value


@app.route("/second-ignored")
def second_ignored():
    t = request.args.get("x")
    r = first("ls", t)
    os.system(r)
    return "ok"


@app.route("/first-returned")
def first_returned():
    t = request.args.get("x")
    r = first(t, "ls")
    os.system(r)
    return "ok"


@app.route("/int")
def int_wrapper():
    n = to_int(request.args.get("n"))
    os.system("ls " + str(n))
    return "ok"


@app.route("/quote")
def quote_wrapper():
    q = quote_it(request.args.get("q"))
    os.system("ls " + q)
    return "ok"


@app.route("/mixed")
def mixed():
    cmd = os.environ["CMD"]
    arg = maybe_quote(cmd, False)
    os.system("ls " + arg)
    return "ok"
