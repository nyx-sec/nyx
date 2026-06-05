<?php
// Phase 05 (Track J.3) — PHP XXE vuln fixture.
//
// The function pulls XML off the request and feeds it to
// `simplexml_load_string` after re-enabling the libxml entity loader
// — so any `<!ENTITY xxe SYSTEM "file:///…">` in the payload is
// resolved and its body substituted into the parsed document.
function run(string $body) {
    libxml_disable_entity_loader(false);
    return simplexml_load_string($body, "SimpleXMLElement", LIBXML_NOENT);
}
