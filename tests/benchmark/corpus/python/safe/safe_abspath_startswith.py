import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name")
    path = os.path.abspath(os.path.join(BASE, name))
    if not path.startswith(BASE + os.sep):
        abort(403)
    return send_file(path)
