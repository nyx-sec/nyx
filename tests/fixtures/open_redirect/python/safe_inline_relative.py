# Safe: inline relative-URL check that also rejects protocol-relative values.
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/login")
def login():
    nxt = request.args.get("next")
    if not nxt.startswith("/") or nxt.startswith("//"):
        return redirect("/")
    return redirect(nxt)


@app.route("/login2")
def login2():
    nxt = request.args.get("next")
    if nxt.startswith("/") and not nxt.startswith("//"):
        return redirect(nxt)
    return redirect("/")
