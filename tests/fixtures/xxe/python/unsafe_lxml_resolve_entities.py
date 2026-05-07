# Unsafe: tainted XML reaches an lxml.etree.XMLParser instance whose
# constructor was explicitly opted into entity resolution
# (`resolve_entities=True`).  lxml is XXE-safe by default, but this
# opt-in form is the documented unsafe escape hatch.  The
# constructor-driven fact is captured in XmlParserConfigResult
# (external_entities=True) and the parser.feed(xml) call adds
# Cap::XXE on top of the otherwise empty sink_caps.
from lxml import etree
from flask import request


def handle():
    body = request.args.get("xml")
    parser = etree.XMLParser(resolve_entities=True)
    parser.feed(body)
    return parser.close()
