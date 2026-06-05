<?php
// Phase 07 (Track J.5) — PHP XPATH_INJECTION benign control fixture.
//
// Same shape as `vuln.php` but routes the attacker-controlled `$name`
// through a small XPath-string-literal escape helper before splicing
// it into the expression, so the selector stays pinned to a single
// node.
function nyx_xpath_escape($s) {
    if (strpos($s, "'") === false) {
        return "'" . $s . "'";
    }
    if (strpos($s, '"') === false) {
        return '"' . $s . '"';
    }
    return "concat('" . str_replace("'", "',\"'\",'", $s) . "')";
}

function run($name) {
    $doc = new DOMDocument();
    $doc->load('xpath_corpus.xml');
    $xp = new DOMXPath($doc);
    $expr = "//user[@name=" . nyx_xpath_escape($name) . "]";
    return $xp->query($expr);
}
