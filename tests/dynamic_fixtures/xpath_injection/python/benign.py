# Phase 07 (Track J.5) — Python XPATH_INJECTION benign control fixture.
#
# Same shape as `vuln.py` but parameterises the XPath via a variable
# binding (the recommended `lxml` defence), so the directory keeps
# returning at most one node.
from lxml import etree


def run(name):
    with open("xpath_corpus.xml", "rb") as f:
        tree = etree.fromstring(f.read())
    finder = etree.XPath("//user[@name=$name]")
    return finder(tree, name=name)
