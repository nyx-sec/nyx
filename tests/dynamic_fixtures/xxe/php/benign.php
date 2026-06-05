<?php
// Phase 05 (Track J.3) — PHP XXE benign fixture.
//
// Same parser surface as `vuln.php` but the entity loader stays
// disabled and the LIBXML_NOENT flag is omitted, so the same payload's
// `<!ENTITY>` block is rejected and no entity body is substituted.
function run(string $body) {
    libxml_disable_entity_loader(true);
    return simplexml_load_string($body);
}
