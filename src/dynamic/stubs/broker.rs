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
use std::collections::{BTreeMap, VecDeque};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
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
    kafka_listener: Option<KafkaListener>,
    sqs_listener: Option<SqsListener>,
    http_listener: Option<HttpBrokerListener>,
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
        let kafka_listener = if kind == StubKind::Kafka {
            start_kafka_listener(log_path.clone())?
        } else {
            None
        };
        let sqs_listener = if kind == StubKind::Sqs {
            start_sqs_listener(log_path.clone())?
        } else {
            None
        };
        let http_listener = if matches!(kind, StubKind::Pubsub | StubKind::Rabbit | StubKind::Nats)
        {
            start_http_broker_listener(kind, log_path.clone())?
        } else {
            None
        };
        Ok(Self {
            kind,
            tempdir: Some(tempdir),
            log_path,
            cursor: Mutex::new(0),
            kafka_listener,
            sqs_listener,
            http_listener,
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
    /// `action<TAB>topic<TAB>payload`
    ///
    /// Older harnesses wrote `topic<TAB>payload`; `drain_events`
    /// still accepts that form and treats it as a `publish` event.
    pub fn record_publish(&self, destination: &str, payload: &str) -> std::io::Result<()> {
        self.record_event("publish", destination, payload)
    }

    /// Record a broker delivery observation.
    pub fn record_delivery(&self, destination: &str, payload: &str) -> std::io::Result<()> {
        self.record_event("deliver", destination, payload)
    }

    /// Record an ack/commit/delete observation. The `payload` field
    /// carries the broker-specific ack token when one exists.
    pub fn record_ack(&self, destination: &str, payload: &str) -> std::io::Result<()> {
        self.record_event("ack", destination, payload)
    }

    fn record_event(&self, action: &str, destination: &str, payload: &str) -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        writeln!(
            f,
            "{}\t{}\t{}",
            action.replace('\t', " "),
            destination.replace('\t', " "),
            payload
        )?;
        Ok(())
    }
}

impl StubProvider for BrokerStub {
    fn kind(&self) -> StubKind {
        self.kind
    }

    fn endpoint(&self) -> String {
        if let Some(listener) = &self.kafka_listener {
            return format!("http://127.0.0.1:{}", listener.port);
        }
        if let Some(listener) = &self.sqs_listener {
            return format!("http://127.0.0.1:{}", listener.port);
        }
        if let Some(listener) = &self.http_listener {
            return format!("http://127.0.0.1:{}", listener.port);
        }
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
            let (action, destination, payload) = parse_broker_log_line(line);
            let event = StubEvent {
                kind: self.kind,
                captured_at_ns: monotonic_ns(),
                summary: format!("{action} {destination}"),
                detail: std::collections::BTreeMap::from([
                    ("action".to_owned(), action.to_owned()),
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

fn parse_broker_log_line(line: &str) -> (&str, &str, &str) {
    let Some((first, rest)) = line.split_once('\t') else {
        return ("publish", line, "");
    };
    if matches!(first, "publish" | "deliver" | "ack" | "nack" | "retry") {
        let (destination, payload) = rest.split_once('\t').unwrap_or((rest, ""));
        (first, destination, payload)
    } else {
        ("publish", first, rest)
    }
}

impl Drop for BrokerStub {
    fn drop(&mut self) {
        if let Some(listener) = &self.kafka_listener {
            listener.shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(format!("127.0.0.1:{}", listener.port));
        }
        if let Some(listener) = &self.sqs_listener {
            listener.shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(format!("127.0.0.1:{}", listener.port));
        }
        if let Some(listener) = &self.http_listener {
            listener.shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(format!("127.0.0.1:{}", listener.port));
        }
        self.tempdir.take();
    }
}

#[derive(Debug)]
struct KafkaListener {
    port: u16,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct KafkaMessage {
    offset: u64,
    value: String,
}

#[derive(Debug, Default)]
struct KafkaState {
    next_offsets: BTreeMap<String, u64>,
    topics: BTreeMap<String, VecDeque<KafkaMessage>>,
    inflight: BTreeMap<(String, u64), KafkaMessage>,
}

fn start_kafka_listener(log_path: PathBuf) -> std::io::Result<Option<KafkaListener>> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(e) => return Err(e),
    };
    let port = listener.local_addr()?.port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(KafkaState::default()));
    let shutdown_clone = Arc::clone(&shutdown);
    let state_clone = Arc::clone(&state);
    std::thread::spawn(move || kafka_accept_loop(listener, shutdown_clone, state_clone, log_path));
    Ok(Some(KafkaListener { port, shutdown }))
}

fn kafka_accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    state: Arc<Mutex<KafkaState>>,
    log_path: PathBuf,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let state = Arc::clone(&state);
        let log_path = log_path.clone();
        std::thread::spawn(move || handle_kafka_connection(stream, state, &log_path));
    }
}

fn handle_kafka_connection(mut stream: TcpStream, state: Arc<Mutex<KafkaState>>, log_path: &Path) {
    let Some(req) = read_http_request(&stream) else {
        return;
    };
    let response = match handle_kafka_request(&req, state, log_path) {
        Ok(body) => http_response_with_type(200, "OK", "application/json", &body),
        Err(body) => http_response_with_type(400, "Bad Request", "application/json", &body),
    };
    let _ = stream.write_all(response.as_bytes());
}

fn handle_kafka_request(
    req: &HttpRequest,
    state: Arc<Mutex<KafkaState>>,
    log_path: &Path,
) -> Result<String, String> {
    let Some((topic, action)) = kafka_path_parts(&req.path) else {
        return Err(json_error("invalid kafka stub path"));
    };
    match action.as_str() {
        "messages" => {
            let mut guard = state.lock().map_err(|_| json_error("internal error"))?;
            let offset = guard.next_offsets.entry(topic.clone()).or_insert(0);
            let message = KafkaMessage {
                offset: *offset,
                value: req.body.clone(),
            };
            *offset += 1;
            guard
                .topics
                .entry(topic.clone())
                .or_default()
                .push_back(message.clone());
            let _ = append_broker_event(log_path, "publish", &topic, &message.value);
            Ok(serde_json::json!({
                "topic": topic,
                "offset": message.offset
            })
            .to_string())
        }
        "records" => {
            let params = parse_form(&req.query);
            let max_records = params
                .get("max")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1)
                .clamp(1, 100);
            let mut guard = state.lock().map_err(|_| json_error("internal error"))?;
            let mut records = Vec::new();
            for _ in 0..max_records {
                let Some(message) = guard.topics.entry(topic.clone()).or_default().pop_front()
                else {
                    break;
                };
                let _ = append_broker_event(log_path, "deliver", &topic, &message.value);
                guard
                    .inflight
                    .insert((topic.clone(), message.offset), message.clone());
                records.push(serde_json::json!({
                    "topic": topic,
                    "offset": message.offset,
                    "value": message.value
                }));
            }
            Ok(serde_json::json!({ "records": records }).to_string())
        }
        "commit" => {
            let params = parse_form(&req.body);
            let offset = params
                .get("offset")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            if let Ok(mut guard) = state.lock()
                && guard.inflight.remove(&(topic.clone(), offset)).is_some()
            {
                let _ = append_broker_event(log_path, "ack", &topic, &offset.to_string());
            }
            Ok(serde_json::json!({ "committed": true }).to_string())
        }
        _ => Err(json_error("invalid kafka stub action")),
    }
}

fn kafka_path_parts(path: &str) -> Option<(String, String)> {
    let mut parts = path.trim_matches('/').split('/');
    if parts.next()? != "topics" {
        return None;
    }
    let topic = parts.next().map(percent_decode)?;
    let action = parts.next()?.to_owned();
    if topic.is_empty() || parts.next().is_some() {
        return None;
    }
    Some((topic, action))
}

fn json_error(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

#[derive(Debug)]
struct SqsListener {
    port: u16,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct SqsMessage {
    message_id: String,
    receipt_handle: String,
    body: String,
    receive_count: u32,
}

#[derive(Debug, Default)]
struct SqsState {
    next_id: u64,
    queues: BTreeMap<String, VecDeque<SqsMessage>>,
    inflight: BTreeMap<String, (String, SqsMessage)>,
}

fn start_sqs_listener(log_path: PathBuf) -> std::io::Result<Option<SqsListener>> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(e) => return Err(e),
    };
    let port = listener.local_addr()?.port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(SqsState::default()));
    let shutdown_clone = Arc::clone(&shutdown);
    let state_clone = Arc::clone(&state);
    std::thread::spawn(move || sqs_accept_loop(listener, shutdown_clone, state_clone, log_path));
    Ok(Some(SqsListener { port, shutdown }))
}

fn sqs_accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    state: Arc<Mutex<SqsState>>,
    log_path: PathBuf,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let state = Arc::clone(&state);
        let log_path = log_path.clone();
        std::thread::spawn(move || handle_sqs_connection(stream, state, &log_path));
    }
}

fn handle_sqs_connection(mut stream: TcpStream, state: Arc<Mutex<SqsState>>, log_path: &Path) {
    let Some(req) = read_http_request(&stream) else {
        return;
    };
    let response = match handle_sqs_request(&req, state, log_path) {
        Ok(body) => http_response(200, "OK", &body),
        Err(body) => http_response(400, "Bad Request", &body),
    };
    let _ = stream.write_all(response.as_bytes());
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: String,
    body: String,
}

fn read_http_request(stream: &TcpStream) -> Option<HttpRequest> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let (path, query) = split_target(&target);

    let mut content_length = 0_usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }

    let mut body = vec![0u8; content_length.min(128 * 1024)];
    if !body.is_empty() {
        reader.read_exact(&mut body).ok()?;
    }
    Some(HttpRequest {
        method,
        path,
        query,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

#[derive(Debug)]
struct HttpBrokerListener {
    port: u16,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct HttpBrokerMessage {
    id: String,
    payload: String,
}

#[derive(Debug, Default)]
struct HttpBrokerState {
    next_id: u64,
    streams: BTreeMap<String, VecDeque<HttpBrokerMessage>>,
    inflight: BTreeMap<String, (String, HttpBrokerMessage)>,
}

fn start_http_broker_listener(
    kind: StubKind,
    log_path: PathBuf,
) -> std::io::Result<Option<HttpBrokerListener>> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(e) => return Err(e),
    };
    let port = listener.local_addr()?.port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(HttpBrokerState::default()));
    let shutdown_clone = Arc::clone(&shutdown);
    let state_clone = Arc::clone(&state);
    std::thread::spawn(move || {
        http_broker_accept_loop(listener, shutdown_clone, kind, state_clone, log_path)
    });
    Ok(Some(HttpBrokerListener { port, shutdown }))
}

fn http_broker_accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    kind: StubKind,
    state: Arc<Mutex<HttpBrokerState>>,
    log_path: PathBuf,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let state = Arc::clone(&state);
        let log_path = log_path.clone();
        std::thread::spawn(move || handle_http_broker_connection(stream, kind, state, &log_path));
    }
}

fn handle_http_broker_connection(
    mut stream: TcpStream,
    kind: StubKind,
    state: Arc<Mutex<HttpBrokerState>>,
    log_path: &Path,
) {
    let Some(req) = read_http_request(&stream) else {
        return;
    };
    let response = match handle_http_broker_request(kind, &req, state, log_path) {
        Ok(body) => http_response_with_type(200, "OK", "application/json", &body),
        Err(body) => http_response_with_type(400, "Bad Request", "application/json", &body),
    };
    let _ = stream.write_all(response.as_bytes());
}

fn handle_http_broker_request(
    kind: StubKind,
    req: &HttpRequest,
    state: Arc<Mutex<HttpBrokerState>>,
    log_path: &Path,
) -> Result<String, String> {
    let Some((destination, action)) = http_broker_path_parts(kind, &req.path) else {
        return Err(json_error("invalid broker stub path"));
    };
    match action.as_str() {
        "messages" if req.method.eq_ignore_ascii_case("GET") => {
            let params = parse_form(&req.query);
            let max_messages = params
                .get("max")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1)
                .clamp(1, 100);
            let mut guard = state.lock().map_err(|_| json_error("internal error"))?;
            let mut messages = Vec::new();
            for _ in 0..max_messages {
                let Some(message) = guard
                    .streams
                    .entry(destination.clone())
                    .or_default()
                    .pop_front()
                else {
                    break;
                };
                let _ = append_broker_event(log_path, "deliver", &destination, &message.payload);
                guard
                    .inflight
                    .insert(message.id.clone(), (destination.clone(), message.clone()));
                messages.push(http_broker_message_json(kind, &destination, &message));
            }
            Ok(serde_json::json!({ "messages": messages }).to_string())
        }
        "messages" => {
            let mut guard = state.lock().map_err(|_| json_error("internal error"))?;
            guard.next_id += 1;
            let id = format!("nyx-{:08}", guard.next_id);
            let message = HttpBrokerMessage {
                id: id.clone(),
                payload: req.body.clone(),
            };
            guard
                .streams
                .entry(destination.clone())
                .or_default()
                .push_back(message);
            let _ = append_broker_event(log_path, "publish", &destination, &req.body);
            Ok(serde_json::json!({ "id": id }).to_string())
        }
        "ack" => {
            let params = parse_form(&req.body);
            let ack_id = params
                .get("ack_id")
                .or_else(|| params.get("id"))
                .cloned()
                .unwrap_or_default();
            if let Ok(mut guard) = state.lock()
                && (ack_id.is_empty() || guard.inflight.remove(&ack_id).is_some())
            {
                let _ = append_broker_event(log_path, "ack", &destination, &ack_id);
            }
            Ok(serde_json::json!({ "acked": true }).to_string())
        }
        _ => Err(json_error("invalid broker stub action")),
    }
}

fn http_broker_path_parts(kind: StubKind, path: &str) -> Option<(String, String)> {
    let expected_root = match kind {
        StubKind::Pubsub => "topics",
        StubKind::Rabbit => "queues",
        StubKind::Nats => "subjects",
        _ => return None,
    };
    let mut parts = path.trim_matches('/').split('/');
    if parts.next()? != expected_root {
        return None;
    }
    let destination = parts.next().map(percent_decode)?;
    let action = parts.next()?.to_owned();
    if destination.is_empty() || parts.next().is_some() {
        return None;
    }
    Some((destination, action))
}

fn http_broker_message_json(
    kind: StubKind,
    destination: &str,
    message: &HttpBrokerMessage,
) -> serde_json::Value {
    match kind {
        StubKind::Pubsub => serde_json::json!({
            "id": &message.id,
            "ack_id": &message.id,
            "data": &message.payload
        }),
        StubKind::Rabbit => serde_json::json!({
            "delivery_tag": &message.id,
            "body": &message.payload
        }),
        StubKind::Nats => serde_json::json!({
            "subject": destination,
            "ack_id": &message.id,
            "data": &message.payload,
            "reply": ""
        }),
        _ => serde_json::json!({}),
    }
}

fn split_target(target: &str) -> (String, String) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    (path.to_owned(), query.to_owned())
}

fn handle_sqs_request(
    req: &HttpRequest,
    state: Arc<Mutex<SqsState>>,
    log_path: &Path,
) -> Result<String, String> {
    let mut params = parse_form(&req.query);
    params.extend(parse_form(&req.body));
    let action = params
        .get("Action")
        .or_else(|| params.get("X-Amz-Target"))
        .map(|s| s.rsplit('.').next().unwrap_or(s).to_owned())
        .unwrap_or_default();
    match action.as_str() {
        "SendMessage" => {
            let queue = queue_name(&params, &req.path);
            let body = params.get("MessageBody").cloned().unwrap_or_default();
            let mut guard = state.lock().map_err(|_| sqs_error("InternalError"))?;
            guard.next_id += 1;
            let message = SqsMessage {
                message_id: format!("nyx-{:08}", guard.next_id),
                receipt_handle: format!("rh-nyx-{:08}", guard.next_id),
                body: body.clone(),
                receive_count: 0,
            };
            guard
                .queues
                .entry(queue.clone())
                .or_default()
                .push_back(message.clone());
            let _ = append_broker_event(log_path, "publish", &queue, &body);
            Ok(format!(
                concat!(
                    "<SendMessageResponse><SendMessageResult>",
                    "<MD5OfMessageBody>{md5}</MD5OfMessageBody>",
                    "<MessageId>{message_id}</MessageId>",
                    "</SendMessageResult><ResponseMetadata>",
                    "<RequestId>nyx-sqs-request</RequestId>",
                    "</ResponseMetadata></SendMessageResponse>"
                ),
                md5 = "00000000000000000000000000000000",
                message_id = xml_escape(&message.message_id)
            ))
        }
        "ReceiveMessage" => {
            let queue = queue_name(&params, &req.path);
            let max_messages = params
                .get("MaxNumberOfMessages")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1)
                .clamp(1, 10);
            let mut guard = state.lock().map_err(|_| sqs_error("InternalError"))?;
            let mut messages = Vec::new();
            for _ in 0..max_messages {
                let Some(mut message) = guard.queues.entry(queue.clone()).or_default().pop_front()
                else {
                    break;
                };
                message.receive_count += 1;
                let _ = append_broker_event(log_path, "deliver", &queue, &message.body);
                guard.inflight.insert(
                    message.receipt_handle.clone(),
                    (queue.clone(), message.clone()),
                );
                messages.push(message);
            }
            let mut body = String::from("<ReceiveMessageResponse><ReceiveMessageResult>");
            for message in messages {
                body.push_str("<Message>");
                body.push_str(&format!(
                    "<MessageId>{}</MessageId>",
                    xml_escape(&message.message_id)
                ));
                body.push_str(&format!(
                    "<ReceiptHandle>{}</ReceiptHandle>",
                    xml_escape(&message.receipt_handle)
                ));
                body.push_str(&format!("<Body>{}</Body>", xml_escape(&message.body)));
                body.push_str("<Attribute><Name>ApproximateReceiveCount</Name><Value>");
                body.push_str(&message.receive_count.to_string());
                body.push_str("</Value></Attribute>");
                body.push_str("</Message>");
            }
            body.push_str(
                "</ReceiveMessageResult><ResponseMetadata><RequestId>nyx-sqs-request</RequestId></ResponseMetadata></ReceiveMessageResponse>",
            );
            Ok(body)
        }
        "DeleteMessage" => {
            let queue = queue_name(&params, &req.path);
            let receipt = params.get("ReceiptHandle").cloned().unwrap_or_default();
            if let Ok(mut guard) = state.lock()
                && guard.inflight.remove(&receipt).is_some()
            {
                let _ = append_broker_event(log_path, "ack", &queue, &receipt);
            }
            Ok(String::from(
                "<DeleteMessageResponse><ResponseMetadata><RequestId>nyx-sqs-request</RequestId></ResponseMetadata></DeleteMessageResponse>",
            ))
        }
        "GetQueueUrl" => {
            let queue = params
                .get("QueueName")
                .cloned()
                .unwrap_or_else(|| queue_name(&params, &req.path));
            Ok(format!(
                concat!(
                    "<GetQueueUrlResponse><GetQueueUrlResult>",
                    "<QueueUrl>http://127.0.0.1/{queue}</QueueUrl>",
                    "</GetQueueUrlResult><ResponseMetadata>",
                    "<RequestId>nyx-sqs-request</RequestId>",
                    "</ResponseMetadata></GetQueueUrlResponse>"
                ),
                queue = xml_escape(&queue)
            ))
        }
        _ => Err(sqs_error("InvalidAction")),
    }
}

fn http_response(status: u16, reason: &str, body: &str) -> String {
    http_response_with_type(status, reason, "text/xml", body)
}

fn http_response_with_type(status: u16, reason: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn sqs_error(code: &str) -> String {
    format!(
        "<ErrorResponse><Error><Type>Sender</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>nyx-sqs-request</RequestId></ErrorResponse>",
        xml_escape(code),
        xml_escape(code)
    )
}

fn parse_form(input: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in input.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(key), percent_decode(value));
    }
    out
}

fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        match bytes[idx] {
            b'+' => {
                out.push(b' ');
                idx += 1;
            }
            b'%' if idx + 2 < bytes.len() => {
                let hi = hex_val(bytes[idx + 1]);
                let lo = hex_val(bytes[idx + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    idx += 3;
                } else {
                    out.push(bytes[idx]);
                    idx += 1;
                }
            }
            b => {
                out.push(b);
                idx += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn queue_name(params: &BTreeMap<String, String>, path: &str) -> String {
    if let Some(url) = params.get("QueueUrl")
        && let Some(queue) = url.trim_end_matches('/').rsplit('/').next()
        && !queue.is_empty()
    {
        return queue.to_owned();
    }
    let path_queue = path.trim_matches('/');
    if !path_queue.is_empty() {
        return path_queue.to_owned();
    }
    "default".to_owned()
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn append_broker_event(
    log_path: &Path,
    action: &str,
    destination: &str,
    payload: &str,
) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)?;
    writeln!(
        f,
        "{}\t{}\t{}",
        action.replace('\t', " "),
        destination.replace('\t', " "),
        payload
    )
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
        let endpoint = stub.endpoint();
        assert!(
            endpoint == "loopback://kafka" || endpoint.starts_with("http://127.0.0.1:"),
            "Kafka endpoint should be loopback fallback or HTTP emulator, got {endpoint}"
        );
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
        assert_eq!(events[0].detail.get("action").unwrap(), "publish");
        assert_eq!(events[0].detail.get("destination").unwrap(), "queue-a");
        assert_eq!(events[0].detail.get("payload").unwrap(), "NYX_PWN_CMDI");
        assert!(stub.drain_events().is_empty(), "drain cursor must advance");
    }

    #[test]
    fn sqs_broker_exposes_http_query_emulator() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Sqs, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://sqs" {
            return;
        }
        assert!(
            endpoint.starts_with("http://127.0.0.1:"),
            "SQS endpoint should be a real SDK-compatible HTTP endpoint, got {endpoint}"
        );
    }

    #[test]
    fn kafka_broker_exposes_http_emulator() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Kafka, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://kafka" {
            return;
        }
        assert!(
            endpoint.starts_with("http://127.0.0.1:"),
            "Kafka endpoint should be a host-side HTTP emulator, got {endpoint}"
        );
    }

    #[test]
    fn remaining_brokers_expose_http_emulators() {
        for kind in [StubKind::Pubsub, StubKind::Rabbit, StubKind::Nats] {
            let dir = TempDir::new().unwrap();
            let stub = BrokerStub::start(kind, dir.path()).unwrap();
            let endpoint = stub.endpoint();
            if endpoint == format!("loopback://{}", kind.tag()) {
                continue;
            }
            assert!(
                endpoint.starts_with("http://127.0.0.1:"),
                "{kind:?} endpoint should be a host-side HTTP emulator, got {endpoint}"
            );
        }
    }

    #[test]
    fn kafka_http_emulator_records_publish_deliver_ack() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Kafka, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://kafka" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("http://127.0.0.1:")
            .parse()
            .unwrap();
        let send = http_post(port, "/topics/orders/messages", "NYX\tPAYLOAD");
        assert!(send.contains(r#""offset":0"#), "{send}");

        let receive = http_get(port, "/topics/orders/records?max=1");
        assert!(receive.contains(r#""value":"NYX\tPAYLOAD""#), "{receive}");

        let commit = http_post(port, "/topics/orders/commit", "offset=0");
        assert!(commit.contains(r#""committed":true"#), "{commit}");

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(actions, vec!["publish", "deliver", "ack"]);
        assert_eq!(events[0].detail.get("destination").unwrap(), "orders");
        assert_eq!(events[1].detail.get("payload").unwrap(), "NYX\tPAYLOAD");
        assert_eq!(events[2].detail.get("payload").unwrap(), "0");
    }

    #[test]
    fn sqs_query_emulator_records_publish_deliver_ack() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Sqs, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://sqs" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("http://127.0.0.1:")
            .parse()
            .unwrap();
        let queue_url = format!("http://127.0.0.1:{port}/jobs");
        let send_body = format!(
            "Action=SendMessage&QueueUrl={}&MessageBody=NYX%09PAYLOAD",
            form_escape(&queue_url)
        );
        let send = http_post(port, "/", &send_body);
        assert!(send.contains("<SendMessageResponse>"), "{send}");

        let receive_body = format!(
            "Action=ReceiveMessage&QueueUrl={}&MaxNumberOfMessages=1",
            form_escape(&queue_url)
        );
        let receive = http_post(port, "/", &receive_body);
        assert!(receive.contains("<Body>NYX\tPAYLOAD</Body>"), "{receive}");
        let receipt = receive
            .split("<ReceiptHandle>")
            .nth(1)
            .and_then(|s| s.split("</ReceiptHandle>").next())
            .unwrap()
            .to_owned();

        let delete_body = format!(
            "Action=DeleteMessage&QueueUrl={}&ReceiptHandle={}",
            form_escape(&queue_url),
            form_escape(&receipt)
        );
        let delete = http_post(port, "/", &delete_body);
        assert!(delete.contains("<DeleteMessageResponse>"), "{delete}");

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(actions, vec!["publish", "deliver", "ack"]);
        assert_eq!(events[0].detail.get("destination").unwrap(), "jobs");
        assert_eq!(events[1].detail.get("payload").unwrap(), "NYX\tPAYLOAD");
        assert_eq!(events[2].detail.get("payload").unwrap(), &receipt);
    }

    #[test]
    fn remaining_http_broker_emulators_record_publish_deliver_ack() {
        let cases = [
            (StubKind::Pubsub, "topics", "projects/p/topics/orders"),
            (StubKind::Rabbit, "queues", "work"),
            (StubKind::Nats, "subjects", "events"),
        ];
        for (kind, root, destination) in cases {
            let dir = TempDir::new().unwrap();
            let stub = BrokerStub::start(kind, dir.path()).unwrap();
            let endpoint = stub.endpoint();
            if endpoint == format!("loopback://{}", kind.tag()) {
                continue;
            }
            let port: u16 = endpoint
                .trim_start_matches("http://127.0.0.1:")
                .parse()
                .unwrap();
            let escaped_destination = form_escape(destination);
            let send = http_post(
                port,
                &format!("/{root}/{escaped_destination}/messages"),
                "NYX\tPAYLOAD",
            );
            assert!(send.contains(r#""id":"nyx-00000001""#), "{send}");

            let receive = http_get(
                port,
                &format!("/{root}/{escaped_destination}/messages?max=1"),
            );
            let parsed: serde_json::Value = serde_json::from_str(response_body(&receive)).unwrap();
            let message = parsed["messages"][0].as_object().unwrap();
            let payload = message
                .get("data")
                .or_else(|| message.get("body"))
                .and_then(|v| v.as_str())
                .unwrap();
            assert_eq!(payload, "NYX\tPAYLOAD");
            let ack_id = message
                .get("ack_id")
                .or_else(|| message.get("delivery_tag"))
                .and_then(|v| v.as_str())
                .unwrap();

            let ack = http_post(
                port,
                &format!("/{root}/{escaped_destination}/ack"),
                &format!("ack_id={}", form_escape(ack_id)),
            );
            assert!(ack.contains(r#""acked":true"#), "{ack}");

            let events = stub.drain_events();
            let actions: Vec<&str> = events
                .iter()
                .map(|ev| ev.detail.get("action").unwrap().as_str())
                .collect();
            assert_eq!(actions, vec!["publish", "deliver", "ack"], "{kind:?}");
            assert_eq!(events[0].detail.get("destination").unwrap(), destination);
            assert_eq!(events[1].detail.get("payload").unwrap(), "NYX\tPAYLOAD");
            assert_eq!(events[2].detail.get("payload").unwrap(), ack_id);
        }
    }

    #[test]
    fn broker_drain_understands_delivery_and_ack_events() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Kafka, dir.path()).unwrap();
        stub.record_delivery("orders", "payload-1").unwrap();
        stub.record_ack("orders", "offset-1").unwrap();
        let events = stub.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "deliver orders");
        assert_eq!(events[1].summary, "ack orders");
        assert_eq!(events[1].detail.get("payload").unwrap(), "offset-1");
    }

    #[test]
    fn broker_drain_preserves_legacy_two_field_publish_lines() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Rabbit, dir.path()).unwrap();
        std::fs::write(stub.log_path(), "work\tlegacy payload\n").unwrap();
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "publish work");
        assert_eq!(events[0].detail.get("action").unwrap(), "publish");
        assert_eq!(events[0].detail.get("payload").unwrap(), "legacy payload");
    }

    fn http_post(port: u16, path: &str, body: &str) -> String {
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    fn http_get(port: u16, path: &str) -> String {
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let req =
            format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nconnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    fn response_body(response: &str) -> &str {
        response.split("\r\n\r\n").nth(1).unwrap_or("")
    }

    fn form_escape(input: &str) -> String {
        let mut out = String::new();
        for b in input.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                b' ' => out.push('+'),
                b => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}
