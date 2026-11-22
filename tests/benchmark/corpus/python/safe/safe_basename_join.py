import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name")
    leaf = os.path.basename(name)
    return send_file(os.path.join(BASE, leaf))
