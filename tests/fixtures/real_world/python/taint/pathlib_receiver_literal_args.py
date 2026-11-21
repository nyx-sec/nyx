from pathlib import Path
from flask import Flask, request

app = Flask(__name__)


@app.route("/w")
def write_literal():
    p = Path(request.args["f"])
    p.write_text("pwned")
    return "ok"


@app.route("/o")
def open_literal():
    p = Path(request.args["f"])
    with p.open("w") as fh:
        fh.write("x")
    return "ok"


@app.route("/r")
def read_literal():
    p = Path(request.args["f"])
    return p.read_text("utf-8")


@app.route("/static")
def fixed_path():
    p = Path("/srv/static/index.html")
    p.write_text("x")
    return p.read_text("utf-8")
