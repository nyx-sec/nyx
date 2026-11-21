import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/cat")
def cat():
    name = request.args.get("name")
    # A `..` check does not remove shell metacharacters.
    if ".." in name:
        return "bad", 400
    os.system("cat " + name)
    return "ok"
