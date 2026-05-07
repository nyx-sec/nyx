# Safe: tainted XML routed through defusedxml, which strips external-entity
# resolution.  Treated as a Sanitizer(XXE), so taint-xxe stays clean.
import defusedxml.ElementTree
from flask import request

def handle():
    body = request.args.get("xml")
    tree = defusedxml.ElementTree.fromstring(body)
    return tree
