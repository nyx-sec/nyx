# Unsafe: Mako TemplateLookup.get_template receives an attacker-controlled
# template name.  A tainted name lets the attacker pick which file under the
# loader directory becomes the rendered template — arbitrary template
# execution, modeled as SSTI.
from mako.lookup import TemplateLookup
from flask import request


def handler():
    name = request.args.get("name")
    lookup = TemplateLookup(directories=["/srv/templates"])
    template = lookup.get_template(name)
    return template.render(user="anon")
