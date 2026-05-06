# Unsafe: jinja2.Template receives a template *source* string built from
# request data.  SSTI fires on the source argument.
from jinja2 import Template
from flask import request


def handler():
    src = request.form["template"]
    t = Template(src)
    return t.render(user="anon")
