// XSS — unsupported fixture.
// Entry is a class method rather than a top-level function.
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Entry: TemplateEngine.render(input)  Cap: HTML_ESCAPE
// Expected verdict: Unsupported

class TemplateEngine {
    render(input) {
        return '<html><body>' + input + '</body></html>';
    }
}

module.exports = { TemplateEngine };
