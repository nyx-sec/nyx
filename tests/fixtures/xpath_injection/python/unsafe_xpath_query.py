# Unsafe: tainted form data concatenated into an XPath expression and passed
# to lxml's `tree.xpath()`.  Suffix matching on `xpath` catches the
# bound-receiver call directly.
from lxml import etree
from flask import request


def lookup():
    tree = etree.parse("users.xml")
    user = request.form["user"]
    expr = "//user[name='" + user + "']"
    return tree.xpath(expr)
