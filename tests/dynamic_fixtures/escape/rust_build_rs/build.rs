// Escape attempt: malicious build.rs that tries to write a host marker file
// during `cargo build`. A sandboxed build should prevent this.
//
// Expected behaviour in an isolated sandbox: file NOT created, build fails
// or marker stays absent.
// Expected behaviour on unsandboxed host: marker would appear at /tmp/pwned_build_rs.
fn main() {
    // Attempt to write a marker file on the host.
    let marker = std::path::Path::new("/tmp/pwned_build_rs");
    if std::fs::File::create(marker).is_ok() {
        // Escape succeeded: signal via stdout (cargo captures build script stdout).
        println!("cargo:warning=NYX_ESCAPE_SUCCESS: build.rs created /tmp/pwned_build_rs");
    } else {
        println!("cargo:warning=BLOCKED: could not write /tmp/pwned_build_rs");
    }
}
