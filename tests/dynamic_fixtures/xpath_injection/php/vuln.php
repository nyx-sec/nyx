<?php
// Phase 07 (Track J.5) — PHP XPATH_INJECTION vuln fixture.
//
// The function string-concatenates the attacker-controlled `$name`
// directly into an XPath expression evaluated by `DOMXPath::query`.
// A payload like `alice' or '1'='1` rewraps the selector as
// `//user[@name='alice' or '1'='1']`, matching every <user> node in
// the staged `xpath_corpus.xml`.
function run($name) {
    $doc = new DOMDocument();
    $doc->load('xpath_corpus.xml');
    $xp = new DOMXPath($doc);
    $expr = "//user[@name='" . $name . "']";
    return $xp->query($expr);
}
