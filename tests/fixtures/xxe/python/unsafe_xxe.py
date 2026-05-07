# Unsafe: tainted XML reaches xml.sax.parseString, which is XXE-vulnerable
# by default in Python's stdlib.
import xml.sax
from flask import request

def handle():
    body = request.args.get("xml")
    return xml.sax.parseString(body, MyHandler())
