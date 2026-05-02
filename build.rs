use std::path::Path;
use std::process::Command;

fn main() {

    // Only relevant when the serve feature is active
    if std::env::var("CARGO_FEATURE_SERVE").is_err() {
        return;
    }

    let dist_dir = Path::new("src/server/assets/dist");
    let index_html = dist_dir.join("index.html");

    // Re-run build.rs only when dist output is missing/changed
    println!("cargo:rerun-if-changed=src/server/assets/dist/index.html");

    if index_html.exists() {
        // Dist already built, nothing to do
        return;
    }

    // Dist missing, try to build frontend
    let frontend_dir = Path::new("frontend");
    if !frontend_dir.join("package.json").exists() {
        emit_placeholder_and_warn(dist_dir);
        return;
    }

    // Run npm install + build
    println!("cargo:warning=Frontend dist not found, running npm install && npm run build...");
    let npm_install = Command::new("npm")
        .arg("install")
        .current_dir(frontend_dir)
        .status();

    match npm_install {
        Ok(s) if s.success() => {}
        _ => {
            emit_placeholder_and_warn(dist_dir);
            return;
        }
    }

    let npm_build = Command::new("npm")
        .arg("run")
        .arg("build")
        .current_dir(frontend_dir)
        .status();

    match npm_build {
        Ok(s) if s.success() => {
            println!("cargo:warning=Frontend built successfully.");
        }
        _ => {
            emit_placeholder_and_warn(dist_dir);
        }
    }
}

fn emit_placeholder_and_warn(dist_dir: &Path) {
    // Create minimal placeholder files so compilation succeeds
    std::fs::create_dir_all(dist_dir).ok();
    std::fs::write(
        dist_dir.join("index.html"),
        "<!DOCTYPE html><html><body><h1>Frontend not built</h1><p>Run: cd frontend &amp;&amp; npm install &amp;&amp; npm run build</p></body></html>",
    )
    .ok();
    std::fs::write(dist_dir.join("app.js"), "// frontend not built\n").ok();
    std::fs::write(dist_dir.join("style.css"), "/* frontend not built */\n").ok();
    println!(
        "cargo:warning=Node.js/npm not available — wrote placeholder frontend assets. Run 'cd frontend && npm install && npm run build' for the real UI."
    );
}
