# Baseline: expression is a compile-time constant.  No taint reaches
# `tree.xpath` so no XPATH_INJECTION finding fires.
from lxml import etree


def lookup():
    tree = etree.parse("users.xml")
    return tree.xpath("//user[@role='admin']")
