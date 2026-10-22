# Unsafe: `startswith("/")` alone accepts `//evil.example`.
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/login")
def login():
    nxt = request.args.get("next")
    if not nxt.startswith("/"):
        return redirect("/")
    return redirect(nxt)
