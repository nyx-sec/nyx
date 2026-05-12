// XSS — negative fixture.
// Safe: HTML-escapes all special characters before output.
// Entry: renderPage(userInput)  Cap: HTML_ESCAPE
// Expected verdict: NotConfirmed

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderPage(userInput) {
    const safe = escapeHtml(userInput);
    process.stdout.write('<html><body>' + safe + '</body></html>\n');
}

module.exports = { renderPage };
