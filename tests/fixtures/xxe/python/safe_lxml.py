# Safe: lxml.etree.parse is XXE-safe by default in modern lxml — external
# entities are not resolved unless `XMLParser(resolve_entities=True)` is
# passed in.  No XXE rule should fire here.
import lxml.etree
from flask import request


def handle():
    body = request.args.get("xml")
    return lxml.etree.parse(body)
