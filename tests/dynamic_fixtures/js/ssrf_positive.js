// SSRF — positive fixture.
// Vulnerable: makes a request to a user-controlled URL.
// Entry: fetch(url)  Cap: SSRF
// Expected verdict: Confirmed (file:///etc/passwd → "daemon:" in output)
// Note: Node.js http/https module does not support file:// scheme.
// We detect the file:// prefix and use fs.readFile directly to simulate
// the SSRF behaviour (same oracle: reads /etc/passwd, outputs "daemon:").

const fs = require('fs');
const http = require('http');
const https = require('https');
const url = require('url');

function fetchUrl(targetUrl) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    const parsed = url.parse(targetUrl);
    if (parsed.protocol === 'file:') {
        // Simulate SSRF via file:// — read local file (oracle expects "daemon:")
        try {
            const content = fs.readFileSync(parsed.pathname || '/', 'utf8');
            process.stdout.write(content);
        } catch (e) {
            // silent
        }
        return;
    }
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.get(targetUrl, (res) => {
        res.on('data', (chunk) => process.stdout.write(chunk));
    });
    req.on('error', () => {});
    req.end();
}

module.exports = { fetchUrl };
