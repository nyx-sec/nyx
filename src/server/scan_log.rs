use jiff::Timestamp;
use serde::Serialize;
use std::str::FromStr;
use std::sync::Mutex;

/// Severity level for a scan log entry.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(()),
        }
    }
}

/// A single structured log entry from a scan.
#[derive(Debug, Clone, Serialize)]
pub struct ScanLogEntry {
    pub timestamp: Timestamp,
    pub level: LogLevel,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Thread-safe collector of structured log entries during a scan.
#[derive(Debug)]
pub struct ScanLogCollector {
    entries: Mutex<Vec<ScanLogEntry>>,
    max_entries: usize,
}

impl Default for ScanLogCollector {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl ScanLogCollector {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            max_entries,
        }
    }

    fn push(&self, entry: ScanLogEntry) {
        if let Ok(mut entries) = self.entries.lock()
            && entries.len() < self.max_entries
        {
            entries.push(entry);
        }
    }

    pub fn info(&self, message: impl Into<String>, file_path: Option<String>) {
        self.push(ScanLogEntry {
            timestamp: Timestamp::now(),
            level: LogLevel::Info,
            message: message.into(),
            file_path,
            detail: None,
        });
    }

    pub fn warn(
        &self,
        message: impl Into<String>,
        file_path: Option<String>,
        detail: Option<String>,
    ) {
        self.push(ScanLogEntry {
            timestamp: Timestamp::now(),
            level: LogLevel::Warn,
            message: message.into(),
            file_path,
            detail,
        });
    }

    pub fn error(
        &self,
        message: impl Into<String>,
        file_path: Option<String>,
        detail: Option<String>,
    ) {
        self.push(ScanLogEntry {
            timestamp: Timestamp::now(),
            level: LogLevel::Error,
            message: message.into(),
            file_path,
            detail,
        });
    }

    /// Clone all entries without clearing.
    pub fn snapshot(&self) -> Vec<ScanLogEntry> {
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Take all entries, leaving the collector empty.
    pub fn drain(&self) -> Vec<ScanLogEntry> {
        self.entries
            .lock()
            .map(|mut e| std::mem::take(&mut *e))
            .unwrap_or_default()
    }
}
