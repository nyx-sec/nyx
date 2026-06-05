// JavaScript JSON_PARSE depth-bomb vuln fixture.
//
// Models a config-driven JSON ingest endpoint that picks the parser
// input based on the request payload tag — `*_DEEP` routes through a
// deeply-nested array literal (256 levels) that drives `JSON.parse`
// past the 64-level depth budget; `*_SHALLOW` routes through a flat
// `[]` parse that leaves the predicate clear.  This shape is needed
// by the differential runner: the vuln-payload attempt and the
// benign-control attempt both load the same fixture, and only the
// payload-routed deep branch trips the `JsonParseExcessiveDepth`
// predicate.
function run(value) {
    const text = Buffer.isBuffer(value)
        ? value.toString('utf8')
        : String(value);
    if (text.indexOf('DEEP') !== -1) {
        const nested = '['.repeat(256) + ']'.repeat(256);
        return JSON.parse(nested);
    }
    return JSON.parse('[]');
}

module.exports = { run };
