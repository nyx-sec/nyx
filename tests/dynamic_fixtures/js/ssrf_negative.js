// SSRF — negative fixture.
// Safe: only allows http/https scheme; file:// and other schemes are rejected.
// Entry: fetchUrl(targetUrl)  Cap: SSRF
// Expected verdict: NotConfirmed

const http = require('http');
const https = require('https');
const url = require('url');

function fetchUrl(targetUrl) {
    const parsed = url.parse(targetUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        process.stdout.write('Scheme not allowed: ' + parsed.protocol + '\n');
        return;
    }
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.get(targetUrl, (res) => {
        res.on('data', (chunk) => process.stdout.write(chunk.toString().substring(0, 64)));
    });
    req.on('error', () => {});
    req.end();
}

module.exports = { fetchUrl };
