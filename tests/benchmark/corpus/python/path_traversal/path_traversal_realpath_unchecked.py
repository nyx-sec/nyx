import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name")
    # realpath resolves symlinks and `..` but does not confine the result.
    path = os.path.realpath(os.path.join(BASE, name))
    return send_file(path)
