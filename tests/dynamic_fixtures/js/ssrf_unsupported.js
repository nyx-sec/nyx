// SSRF — unsupported fixture.
// Entry takes an already-parsed URL object, not a string.
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Entry: fetchParsed(parsedUrl)  Cap: SSRF
// Expected verdict: Unsupported

const http = require('http');

function fetchParsed(parsedUrl) {
    if (!parsedUrl || typeof parsedUrl !== 'object') {
        return;
    }
    const req = http.get(parsedUrl, (res) => {
        res.on('data', (d) => process.stdout.write(d));
    });
    req.on('error', () => {});
    req.end();
}

module.exports = { fetchParsed };
