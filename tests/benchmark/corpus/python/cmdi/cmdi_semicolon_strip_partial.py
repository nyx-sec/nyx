import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args["host"]
    host = host.replace(";", "")
    os.system("ping -c 1 " + host)
    return "ok"
