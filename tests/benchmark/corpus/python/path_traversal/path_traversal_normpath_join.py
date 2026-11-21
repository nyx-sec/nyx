import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name")
    # normpath is lexical: `/etc/passwd` joined under BASE is `/etc/passwd`.
    path = os.path.normpath(os.path.join(BASE, name))
    return send_file(path)
