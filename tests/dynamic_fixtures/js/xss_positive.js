// XSS — positive fixture.
// Vulnerable: echoes raw user input into HTML output without escaping.
// Entry: renderPage(userInput)  Cap: HTML_ESCAPE
// Expected verdict: Confirmed (<script>NYX_XSS_CONFIRMED</script> echoed)

function renderPage(userInput) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    // Unescaped output — script tags pass through verbatim.
    process.stdout.write('<html><body>' + userInput + '</body></html>\n');
}

module.exports = { renderPage };
