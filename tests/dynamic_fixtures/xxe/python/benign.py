"""Phase 05 (Track J.3) — Python XXE benign fixture.

Same parser surface as `vuln.py` but the parser is configured with
`resolve_entities=False` and `no_network=True`, so the same payload's
`<!ENTITY>` block is rejected and no entity body is substituted.
"""
from lxml import etree


def run(body: bytes):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(body, parser=parser)
