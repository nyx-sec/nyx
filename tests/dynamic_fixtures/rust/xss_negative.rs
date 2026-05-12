/// XSS — negative fixture.
///
/// Safe function: HTML-escapes user input before embedding in output.
/// Expected verdict: NotConfirmed (XSS payload is escaped; no raw script tag in output).
/// Cap: HTML_ESCAPE  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Safe: escape all HTML special characters before rendering.
    let escaped = payload
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;");
    let html = format!("<div class='comment'>{}</div>", escaped);
    println!("{}", html);
}
