# Fixture: spec derived via FromCallgraphEntry (rule id matches `*.http.*`,
# entry point classified as HttpRoute).
from flask import Flask, request

app = Flask(__name__)

@app.route("/echo")
def echo():
    return request.args.get("q", "")
