/// File I/O — unsupported entry-kind fixture.
///
/// Vulnerable logic lives inside a struct method. The test creates a Diag
/// with an unsupported entry kind so `HarnessSpec::from_finding` returns
/// `Err(UnsupportedReason::EntryKindUnsupported)`.
///
/// Expected verdict: Unsupported(EntryKindUnsupported)
/// Cap: FILE_IO
pub struct FileService;

impl FileService {
    pub fn read(&self, path: &str) -> String {
        // Vulnerable: path traversal — user controls the path.
        std::fs::read_to_string(path).unwrap_or_default()
    }
}
