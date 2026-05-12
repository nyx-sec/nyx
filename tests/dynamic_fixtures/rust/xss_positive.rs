/// XSS — positive fixture.
///
/// Vulnerable function: echoes user input directly into HTML without escaping.
/// Expected verdict: Confirmed (XSS payload echoed verbatim to output).
/// Cap: HTML_ESCAPE  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Vulnerable: direct string interpolation into HTML output.
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let html = format!("<div class='comment'>{}</div>", payload);
    println!("{}", html);
}
