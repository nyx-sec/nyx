import os
import html
from flask import Flask, request
app = Flask(__name__)

@app.route("/b")
def b():
    name = request.args.get("name")
    greeting = html.escape(request.args.get("greet"))
    d = {}
    d[name] = 1
    for k in d:
        os.system(k)
    return greeting
