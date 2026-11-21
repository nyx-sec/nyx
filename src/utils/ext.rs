pub fn lowercase_ext(path: &std::path::Path) -> Option<&'static str> {
    path.extension().and_then(|s| match s.to_str()? {
        "rs" | "RS" => Some("rs"),
        "c" => Some("c"),
        // Real-world C++ codebases overwhelmingly use `.cc` / `.cxx` /
        // `.hpp` / `.hh` / `.h++` rather than the `.cpp` synthetic-fixture
        // extension.  All map to the same tree-sitter-cpp grammar.  `.h`
        // is intentionally NOT mapped, it's also valid C and
        // disambiguating without a build system is brittle.
        "cpp" | "c++" | "cc" | "cxx" | "hpp" | "hxx" | "hh" | "h++" => Some("cpp"),
        "java" => Some("java"),
        "go" => Some("go"),
        "php" => Some("php"),
        "py" | "PY" => Some("py"),
        // `.mts` / `.cts` and `.mjs` / `.cjs` are the ES-module and CommonJS
        // forms of TypeScript and JavaScript; the grammars are the same.
        "ts" | "TSX" | "tsx" | "mts" | "cts" => Some("ts"),
        "js" | "jsx" | "mjs" | "cjs" => Some("js"),
        "rb" | "RB" => Some("rb"),
        "ejs" | "EJS" => Some("ejs"),
        _ => None,
    })
}

#[test]
fn lowercase_ext_recognises_known_extensions() {
    let cases = [
        ("file.rs", Some("rs")),
        ("FILE.RS", Some("rs")),
        ("main.cpp", Some("cpp")),
        ("script.PY", Some("py")),
        ("index.tsx", Some("ts")),
        ("style.css", None), // unsupported
    ];

    for (file, expected) in cases {
        assert_eq!(
            lowercase_ext(std::path::Path::new(file)),
            expected,
            "case: {file}"
        );
    }
}

#[test]
fn lowercase_ext_all_supported_extensions() {
    use std::path::Path;
    let cases: &[(&str, &str)] = &[
        ("main.rs", "rs"),
        ("main.RS", "rs"),
        ("util.c", "c"),
        ("util.cpp", "cpp"),
        ("util.c++", "cpp"),
        ("util.cc", "cpp"),
        ("util.cxx", "cpp"),
        ("util.hpp", "cpp"),
        ("util.hxx", "cpp"),
        ("util.hh", "cpp"),
        ("util.h++", "cpp"),
        ("App.java", "java"),
        ("server.go", "go"),
        ("index.php", "php"),
        ("script.py", "py"),
        ("script.PY", "py"),
        ("app.ts", "ts"),
        ("app.tsx", "ts"),
        ("app.TSX", "ts"),
        ("bundle.js", "js"),
        ("view.jsx", "js"),
        ("server.mjs", "js"),
        ("config.cjs", "js"),
        ("server.mts", "ts"),
        ("config.cts", "ts"),
        ("app.rb", "rb"),
        ("app.RB", "rb"),
    ];
    for (file, expected) in cases {
        assert_eq!(
            lowercase_ext(Path::new(file)),
            Some(*expected),
            "file: {file}"
        );
    }
}

#[test]
fn lowercase_ext_unsupported_extensions_return_none() {
    use std::path::Path;
    let unsupported = [
        "style.css",
        "index.html",
        "data.json",
        "README.md",
        "lock.lock",
        "image.png",
    ];
    for file in unsupported {
        assert_eq!(lowercase_ext(Path::new(file)), None, "file: {file}");
    }
}

#[test]
fn lowercase_ext_path_without_extension_returns_none() {
    use std::path::Path;
    assert_eq!(lowercase_ext(Path::new("Makefile")), None);
    assert_eq!(lowercase_ext(Path::new("README")), None);
    assert_eq!(lowercase_ext(Path::new("")), None);
}

#[test]
fn lowercase_ext_uses_final_extension_only() {
    use std::path::Path;
    // A file named "archive.tar.gz" has extension "gz", not "tar"
    assert_eq!(lowercase_ext(Path::new("archive.tar.gz")), None);
    // "backup.rs.bak" has extension "bak"
    assert_eq!(lowercase_ext(Path::new("backup.rs.bak")), None);
}

#[test]
fn lowercase_ext_works_with_directory_prefixes() {
    use std::path::Path;
    assert_eq!(lowercase_ext(Path::new("src/main.rs")), Some("rs"));
    assert_eq!(
        lowercase_ext(Path::new("/absolute/path/to/app.py")),
        Some("py")
    );
    assert_eq!(lowercase_ext(Path::new("a/b/c/d.js")), Some("js"));
}
