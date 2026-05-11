# Safe: user-supplied substring routed through the project-local
# `escape_xpath` helper before being concatenated into the XPath expression.
# The sanitizer clears the XPATH_INJECTION cap so the sink does not fire.
from lxml import etree
from flask import request


def escape_xpath(raw):
    return raw.replace("'", "&apos;")


def lookup():
    tree = etree.parse("users.xml")
    user = request.form["user"]
    safe = escape_xpath(user)
    expr = "//user[name='" + safe + "']"
    return tree.xpath(expr)
