//! Runtime broker loopback stubs.
//!
//! These providers give broker-shaped harnesses the same lifecycle as
//! SQL, HTTP, Redis, filesystem, and mock stubs: the verifier starts a
//! host-side provider, publishes a stable endpoint into the sandbox
//! environment, and drains structured events after each payload run.
//! The per-language source snippets still provide the in-process
//! delivery API used by today's message-handler harnesses; this
//! provider is the shared recording and routing surface those snippets
//! can use.

use super::{StubEvent, StubKind, StubProvider, monotonic_ns};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::TempDir;

/// Broker-cap stub. Endpoint is a stable loopback URI; the companion
/// recording endpoint is a log file path the sandbox harness can
/// append one publish event per line to.
#[derive(Debug)]
pub struct BrokerStub {
    kind: StubKind,
    tempdir: Option<TempDir>,
    log_path: PathBuf,
    cursor: Mutex<u64>,
}

impl BrokerStub {
    /// Start a broker stub rooted near `workdir`.
    pub fn start(kind: StubKind, workdir: &Path) -> std::io::Result<Self> {
        debug_assert!(kind.is_broker(), "BrokerStub only supports broker kinds");
        let tempdir = TempDir::new_in(workdir).or_else(|_| TempDir::new())?;
        let log_path = tempdir
            .path()
            .join(format!("nyx_{}_stub.events.log", kind.tag()));
        std::fs::File::create(&log_path)?;
        Ok(Self {
            kind,
            tempdir: Some(tempdir),
            log_path,
            cursor: Mutex::new(0),
        })
    }

    /// Path to the append-only event log consumed by `drain_events`.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Host-side helper used by tests and future native broker
    /// adapters. The line format is intentionally simple so shell,
    /// Java, Python, Node, Go, PHP, Ruby, and Rust harnesses can append
    /// it without a JSON dependency:
    ///
    /// `topic<TAB>payload`
    pub fn record_publish(&self, destination: &str, payload: &str) -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        writeln!(f, "{}\t{}", destination.replace('\t', " "), payload)?;
        Ok(())
    }
}

impl StubProvider for BrokerStub {
    fn kind(&self) -> StubKind {
        self.kind
    }

    fn endpoint(&self) -> String {
        format!("loopback://{}", self.kind.tag())
    }

    fn recording_endpoint(&self) -> Option<(&'static str, String)> {
        Some((
            self.kind.broker_log_env_var()?,
            self.log_path.to_string_lossy().into_owned(),
        ))
    }

    fn drain_events(&self) -> Vec<StubEvent> {
        let mut cursor = match self.cursor.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let file = match std::fs::File::open(&self.log_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        use std::io::Seek;
        let mut reader = BufReader::new(file);
        if reader.seek(std::io::SeekFrom::Start(*cursor)).is_err() {
            return Vec::new();
        }

        let mut events = Vec::new();
        let mut bytes_read = 0_u64;
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = match reader.read_line(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            bytes_read += n as u64;
            let line = buf.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue;
            }
            let (destination, payload) = line.split_once('\t').unwrap_or((line, ""));
            let event = StubEvent {
                kind: self.kind,
                captured_at_ns: monotonic_ns(),
                summary: format!("publish {destination}"),
                detail: std::collections::BTreeMap::from([
                    ("destination".to_owned(), destination.to_owned()),
                    ("payload".to_owned(), payload.to_owned()),
                ]),
            };
            events.push(event);
        }
        *cursor += bytes_read;
        events
    }
}

impl Drop for BrokerStub {
    fn drop(&mut self) {
        self.tempdir.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn broker_start_creates_recording_log() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Kafka, dir.path()).unwrap();
        assert!(stub.log_path().exists());
        assert_eq!(stub.endpoint(), "loopback://kafka");
        assert_eq!(
            stub.recording_endpoint().unwrap().0,
            StubKind::Kafka.broker_log_env_var().unwrap()
        );
    }

    #[test]
    fn broker_publish_lands_in_drain_events() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Sqs, dir.path()).unwrap();
        stub.record_publish("queue-a", "NYX_PWN_CMDI").unwrap();
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, StubKind::Sqs);
        assert_eq!(events[0].summary, "publish queue-a");
        assert_eq!(events[0].detail.get("destination").unwrap(), "queue-a");
        assert_eq!(events[0].detail.get("payload").unwrap(), "NYX_PWN_CMDI");
        assert!(stub.drain_events().is_empty(), "drain cursor must advance");
    }
}
