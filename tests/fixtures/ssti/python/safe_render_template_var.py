# Safe-template-var: Flask `render_template("file.html", **vars)`.  The
# first arg is a *file path* (constant), variables carry user input but
# never become template source.  Must NOT fire SSTI.
from flask import render_template, request


def handler():
    return render_template("greeting.html", name=request.args.get("name"))
