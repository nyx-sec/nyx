/// SSRF — unsupported entry-kind fixture.
///
/// Vulnerable logic lives inside a struct method. The test creates a Diag
/// with an unsupported entry kind so `HarnessSpec::from_finding` returns
/// `Err(UnsupportedReason::EntryKindUnsupported)`.
///
/// Expected verdict: Unsupported(EntryKindUnsupported)
/// Cap: SSRF
pub struct HttpClient;

impl HttpClient {
    pub fn get(&self, url: &str) -> String {
        // Vulnerable: user controls the URL — SSRF.
        if let Some(path) = url.strip_prefix("file://") {
            std::fs::read_to_string(path).unwrap_or_default()
        } else {
            format!("fetching: {}", url)
        }
    }
}
