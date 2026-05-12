/// XSS — unsupported entry-kind fixture.
///
/// The vulnerable logic lives inside a struct method. The test creates a Diag
/// with Confidence::Low, so `HarnessSpec::from_finding` returns
/// `Err(UnsupportedReason::ConfidenceTooLow)`.
///
/// Expected verdict: Unsupported(ConfidenceTooLow)
/// Cap: HTML_ESCAPE
pub struct PageRenderer;

impl PageRenderer {
    pub fn render(&self, user_input: &str) -> String {
        // Vulnerable: no HTML escaping.
        format!("<div>{}</div>", user_input)
    }
}
