# Safe: Mako TemplateLookup.get_template receives a literal template name.
# No tainted flow into the loader-path argument, no SSTI.
from mako.lookup import TemplateLookup


def handler():
    lookup = TemplateLookup(directories=["/srv/templates"])
    template = lookup.get_template("home.mako")
    return template.render(user="anon")
