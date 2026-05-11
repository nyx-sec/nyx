# Unsafe: Jinja2 Environment.get_template receives an attacker-controlled
# template name.  Tainted name lets the attacker swap the resolved template,
# yielding arbitrary template execution.  Modeled as SSTI on the loader-path
# argument.
from jinja2 import Environment, FileSystemLoader
from flask import request


def handler():
    name = request.args.get("page")
    env = Environment(loader=FileSystemLoader("/srv/templates"))
    template = env.get_template(name)
    return template.render(user="anon")
