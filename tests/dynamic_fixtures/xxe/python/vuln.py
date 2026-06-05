"""Phase 05 (Track J.3) — Python XXE vuln fixture.

The function pulls XML bytes off the request and feeds them straight
to `lxml.etree.XMLParser(resolve_entities=True)`, so any
`<!ENTITY xxe SYSTEM "file:///…">` in the payload is resolved and its
body substituted into the parsed tree.
"""
from lxml import etree


def run(body: bytes):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(body, parser=parser)
