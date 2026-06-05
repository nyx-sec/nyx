// Phase 07 (Track J.5) — JavaScript XPATH_INJECTION benign control fixture.
//
// Same shape as `vuln.js` but routes the attacker-controlled `name`
// through a small XPath-string-literal escape helper before splicing
// it into the expression, so the selector stays pinned to a single
// node.
const fs = require('fs');
const xpath = require('xpath');
const { DOMParser } = require('@xmldom/xmldom');

function escapeXpathString(s) {
    if (s.indexOf("'") < 0) {
        return "'" + s + "'";
    }
    if (s.indexOf('"') < 0) {
        return '"' + s + '"';
    }
    return "concat('" + s.replace(/'/g, "',\"'\",'") + "')";
}

function run(name) {
    const xml = fs.readFileSync('xpath_corpus.xml', 'utf8');
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    const expr = "//user[@name=" + escapeXpathString(name) + "]";
    return xpath.select(expr, doc);
}

module.exports = { run };
