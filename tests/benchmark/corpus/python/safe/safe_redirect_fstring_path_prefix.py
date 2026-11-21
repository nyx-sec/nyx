from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    uid = request.args.get("id")
    return redirect(f"/users/{uid}")
