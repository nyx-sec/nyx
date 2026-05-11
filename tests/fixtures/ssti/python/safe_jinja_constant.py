# Safe: jinja2.Template receives a constant template source.  Variables
# passed at render time are not template source and do not activate SSTI.
from jinja2 import Template
from flask import request


def handler():
    t = Template("Hello, {{ name }}")
    return t.render(name=request.args.get("name"))
