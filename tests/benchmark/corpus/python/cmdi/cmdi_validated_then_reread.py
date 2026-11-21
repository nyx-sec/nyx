import os
from flask import Flask, request

app = Flask(__name__)


def validate_page(v):
    return v.isdigit()


@app.route("/page")
def page():
    value = request.args["page"]
    if not validate_page(value):
        return "bad", 400
    value = request.args["sort"]
    os.system("sort -k " + value + " data.txt")
    return "ok"
