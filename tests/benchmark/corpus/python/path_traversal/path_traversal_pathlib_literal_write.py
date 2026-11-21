from pathlib import Path
from flask import Flask, request

app = Flask(__name__)


@app.route("/touch")
def touch():
    target = Path(request.args["f"])
    target.write_text("pwned")
    return "ok"
