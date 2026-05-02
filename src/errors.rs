//! Error types used throughout the scanner.
//!
//! [`NyxError`] wraps I/O, TOML parse, SQLite, tree-sitter, and connection-pool
//! errors into a single enum. [`NyxResult<T>`] is the standard return type alias.
//!
//! [`ConfigError`] and [`ConfigErrorKind`] carry structured config-validation
//! diagnostics (section, field, message, kind) so callers can format them
//! consistently without ad-hoc string matching.

use serde::Serialize;
use serde::de::StdError;
use std::fmt;
use std::sync::PoisonError;
use thiserror::Error;

pub type NyxResult<T, E = NyxError> = Result<T, E>;

// ─── Config validation ──────────────────────────────────────────────────────

/// A single config validation error with structured metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigError {
    pub section: String,
    pub field: String,
    pub message: String,
    pub kind: ConfigErrorKind,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}.{}] {}", self.section, self.field, self.message)
    }
}

/// Category of config validation error.
#[derive(Debug, Clone, Serialize)]
pub enum ConfigErrorKind {
    OutOfRange,
    InvalidValue,
    EmptyRequired,
    Conflict,
}

#[derive(Debug, Error)]
pub enum NyxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("SQLite error: {0}")]
    Sql(#[from] rusqlite::Error),

    #[error("tree-sitter error: {0}")]
    TreeSitter(#[from] tree_sitter::LanguageError),

    #[error("connection-pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("time error: {0}")]
    Time(#[from] std::time::SystemTimeError),

    #[error("poisoned lock: {0}")]
    Poison(String),

    #[error(transparent)]
    Other(#[from] Box<dyn StdError + Send + Sync + 'static>),

    #[error("{0}")]
    Msg(String),

    #[error("config validation failed:\n{}", .0.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    ConfigValidation(Vec<ConfigError>),
}

impl<T> From<PoisonError<T>> for NyxError
where
    T: fmt::Debug,
{
    fn from(err: PoisonError<T>) -> Self {
        NyxError::Poison(err.to_string())
    }
}

impl From<&str> for NyxError {
    fn from(s: &str) -> Self {
        NyxError::Msg(s.to_owned())
    }
}

impl From<String> for NyxError {
    fn from(s: String) -> Self {
        NyxError::Msg(s)
    }
}

impl From<Box<dyn std::error::Error>> for NyxError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        NyxError::Msg(err.to_string())
    }
}

#[test]
fn io_conversion_retains_message() {
    let e = std::io::Error::other("boom!");
    let n: NyxError = e.into();
    assert!(matches!(n, NyxError::Io(_)));
    assert!(n.to_string().contains("boom"));
}

#[test]
fn poison_conversion_maps_correct_variant() {
    let lock = std::sync::Arc::new(std::sync::Mutex::new(()));

    {
        let lock2 = std::sync::Arc::clone(&lock);
        std::thread::spawn(move || {
            let _guard = lock2.lock().unwrap();
            panic!("intentional – poison the mutex");
        })
        .join()
        .ok();
    }

    let poison = lock.lock().unwrap_err();
    let nyx: NyxError = poison.into();

    assert!(matches!(nyx, NyxError::Poison(_)));
}

#[test]
fn simple_string_into_msg() {
    let nyx: NyxError = "plain msg".into();
    assert!(matches!(nyx, NyxError::Msg(s) if s == "plain msg"));
}

#[test]
fn string_owned_into_msg() {
    let s = String::from("owned message");
    let nyx: NyxError = s.into();
    assert!(matches!(nyx, NyxError::Msg(ref m) if m == "owned message"));
    assert!(nyx.to_string().contains("owned message"));
}

#[test]
fn box_dyn_error_into_msg() {
    let boxed: Box<dyn std::error::Error> = Box::new(std::io::Error::other("inner error"));
    let nyx: NyxError = boxed.into();
    // The From<Box<dyn std::error::Error>> impl wraps as Msg
    assert!(matches!(nyx, NyxError::Msg(_)));
    assert!(nyx.to_string().contains("inner error"));
}

#[test]
fn config_error_display_includes_section_field_and_message() {
    let err = ConfigError {
        section: "server".to_string(),
        field: "port".to_string(),
        message: "must be non-zero".to_string(),
        kind: ConfigErrorKind::OutOfRange,
    };
    let s = err.to_string();
    assert!(s.contains("server"), "should mention section: {s}");
    assert!(s.contains("port"), "should mention field: {s}");
    assert!(
        s.contains("must be non-zero"),
        "should mention message: {s}"
    );
}

#[test]
fn config_error_kind_debug_names() {
    let kinds = [
        ConfigErrorKind::OutOfRange,
        ConfigErrorKind::InvalidValue,
        ConfigErrorKind::EmptyRequired,
        ConfigErrorKind::Conflict,
    ];
    let names = ["OutOfRange", "InvalidValue", "EmptyRequired", "Conflict"];
    for (kind, name) in kinds.iter().zip(names.iter()) {
        assert!(format!("{kind:?}").contains(name));
    }
}

#[test]
fn nyx_error_config_validation_display_lists_all_errors() {
    let errs = vec![
        ConfigError {
            section: "scanner".to_string(),
            field: "threads".to_string(),
            message: "must be > 0".to_string(),
            kind: ConfigErrorKind::OutOfRange,
        },
        ConfigError {
            section: "output".to_string(),
            field: "format".to_string(),
            message: "unrecognised value".to_string(),
            kind: ConfigErrorKind::InvalidValue,
        },
    ];
    let nyx = NyxError::ConfigValidation(errs);
    let s = nyx.to_string();
    assert!(s.contains("scanner"), "should list first error: {s}");
    assert!(s.contains("output"), "should list second error: {s}");
    assert!(s.contains("must be > 0"), "should include message: {s}");
}

#[test]
fn nyx_result_ok_variant_propagates_value() {
    let value = 42;
    let result: NyxResult<u32> = Ok(value);
    match result {
        Ok(actual) => assert_eq!(actual, value),
        Err(err) => panic!("expected Ok result, got {err}"),
    }
}

#[test]
fn nyx_result_err_variant_contains_error() {
    let message = "oops".to_string();
    let result: NyxResult<u32> = Err(NyxError::Msg(message.clone()));
    match result {
        Ok(value) => panic!("expected Err result, got Ok({value})"),
        Err(err) => assert!(err.to_string().contains(&message)),
    }
}
