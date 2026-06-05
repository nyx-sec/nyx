# Phase 07 (Track J.5) — Python XPATH_INJECTION vuln fixture.
#
# The function string-concatenates the attacker-controlled `name`
# directly into an XPath expression evaluated by `lxml.etree`'s
# `xpath` method.  A payload like `alice' or '1'='1` rewraps the
# selector as `//user[@name='alice' or '1'='1']`, matching every
# <user> node in the staged `xpath_corpus.xml`.
from lxml import etree


def run(name):
    with open("xpath_corpus.xml", "rb") as f:
        tree = etree.fromstring(f.read())
    expr = "//user[@name='" + name + "']"
    return tree.xpath(expr)
