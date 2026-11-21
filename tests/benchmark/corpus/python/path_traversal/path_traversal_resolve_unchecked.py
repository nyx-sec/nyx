from pathlib import Path
from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name")
    path = Path(BASE, name).resolve()
    return send_file(path)
