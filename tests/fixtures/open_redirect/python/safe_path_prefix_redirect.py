# Safe: fixed same-origin path prefix on the redirect target.
import flask
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    uid = request.args.get("id")
    return redirect(f"/users/{uid}")


@app.route("/go2")
def go2():
    # A literal target is fixed, whatever the `flask` module object carries.
    flask.session["redirect"] = True
    return flask.redirect("/target")
