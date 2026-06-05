// Phase 07 (Track J.5) — JavaScript XPATH_INJECTION vuln fixture.
//
// The function string-concatenates the attacker-controlled `name`
// directly into an XPath expression evaluated by the npm `xpath`
// package's `select`.  A payload like `alice' or '1'='1` rewraps the
// selector as `//user[@name='alice' or '1'='1']`, matching every
// <user> node in the staged `xpath_corpus.xml`.
const fs = require('fs');
const xpath = require('xpath');
const { DOMParser } = require('@xmldom/xmldom');

function run(name) {
    const xml = fs.readFileSync('xpath_corpus.xml', 'utf8');
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    const expr = "//user[@name='" + name + "']";
    return xpath.select(expr, doc);
}

module.exports = { run };
