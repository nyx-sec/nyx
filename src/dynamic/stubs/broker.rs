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
//!
//! The Rabbit provider intentionally implements a bounded AMQP 0-9-1
//! contract rather than a full broker: connection/channel open, exchange
//! declare, queue declare/bind/delete, basic publish/get/consume/deliver,
//! qos, ack/nack/reject with requeue, cancel, publisher confirms, close,
//! and heartbeats. It does not emulate broker policies such as TLS,
//! federation, DLX, permissions, or exchange-type routing beyond direct
//! queue bindings.
//!
//! Kafka and Pub/Sub follow the same bounded-provider model. Kafka
//! speaks enough of the binary protocol for metadata, produce, assigned
//! partition fetch/list-offsets, and basic consumer-group compatibility.
//! Pub/Sub exposes a plaintext h2/gRPC emulator for create-topic,
//! create-subscription, publish, pull, acknowledge, and the single
//! response shape used by streaming pull clients.

use super::{StubEvent, StubKind, StubProvider, monotonic_ns};
use prost::Message;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
    pubsub_grpc_listener: Option<PubsubGrpcListener>,
    http_listener: Option<HttpBrokerListener>,
    rabbit_amqp_listener: Option<RabbitAmqpListener>,
    nats_listener: Option<NatsListener>,
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
        let pubsub_grpc_listener = if kind == StubKind::Pubsub {
            start_pubsub_grpc_listener(log_path.clone())?
        } else {
            None
        };
        let http_listener = if matches!(kind, StubKind::Pubsub | StubKind::Rabbit) {
            start_http_broker_listener(kind, log_path.clone())?
        } else {
            None
        };
        let rabbit_amqp_listener = if kind == StubKind::Rabbit {
            start_rabbit_amqp_listener(log_path.clone())?
        } else {
            None
        };
        let nats_listener = if kind == StubKind::Nats {
            start_nats_listener(log_path.clone())?
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
            pubsub_grpc_listener,
            http_listener,
            rabbit_amqp_listener,
            nats_listener,
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
            return format!("kafka://127.0.0.1:{}", listener.port);
        }
        if let Some(listener) = &self.sqs_listener {
            return format!("http://127.0.0.1:{}", listener.port);
        }
        if let Some(listener) = &self.rabbit_amqp_listener {
            return format!("amqp://127.0.0.1:{}/%2f", listener.port);
        }
        if let Some(listener) = &self.pubsub_grpc_listener {
            return format!("pubsub://127.0.0.1:{}", listener.port);
        }
        if let Some(listener) = &self.http_listener {
            return format!("http://127.0.0.1:{}", listener.port);
        }
        if let Some(listener) = &self.nats_listener {
            return format!("nats://127.0.0.1:{}", listener.port);
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
        if let Some(listener) = &self.pubsub_grpc_listener {
            listener.shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(format!("127.0.0.1:{}", listener.port));
        }
        if let Some(listener) = &self.http_listener {
            listener.shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(format!("127.0.0.1:{}", listener.port));
        }
        if let Some(listener) = &self.rabbit_amqp_listener {
            listener.shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(format!("127.0.0.1:{}", listener.port));
        }
        if let Some(listener) = &self.nats_listener {
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
    let mut prefix = [0_u8; 4];
    let n = stream.peek(&mut prefix).unwrap_or(0);
    if n > 0 && matches!(prefix[0], b'G' | b'P' | b'D' | b'H') {
        let Some(req) = read_http_request(&stream) else {
            return;
        };
        let response = match handle_kafka_request(&req, state, log_path) {
            Ok(body) => http_response_with_type(200, "OK", "application/json", &body),
            Err(body) => http_response_with_type(400, "Bad Request", "application/json", &body),
        };
        let _ = stream.write_all(response.as_bytes());
        return;
    }
    handle_kafka_binary_connection(stream, state, log_path);
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

const KAFKA_API_PRODUCE: i16 = 0;
const KAFKA_API_FETCH: i16 = 1;
const KAFKA_API_LIST_OFFSETS: i16 = 2;
const KAFKA_API_METADATA: i16 = 3;
const KAFKA_API_OFFSET_COMMIT: i16 = 8;
const KAFKA_API_OFFSET_FETCH: i16 = 9;
const KAFKA_API_FIND_COORDINATOR: i16 = 10;
const KAFKA_API_JOIN_GROUP: i16 = 11;
const KAFKA_API_HEARTBEAT: i16 = 12;
const KAFKA_API_LEAVE_GROUP: i16 = 13;
const KAFKA_API_SYNC_GROUP: i16 = 14;
const KAFKA_API_API_VERSIONS: i16 = 18;

fn handle_kafka_binary_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<KafkaState>>,
    log_path: &Path,
) {
    loop {
        let mut len_buf = [0_u8; 4];
        if stream.read_exact(&mut len_buf).is_err() {
            break;
        }
        let len = i32::from_be_bytes(len_buf);
        if len <= 0 || len > 1024 * 1024 {
            break;
        }
        let mut body = vec![0_u8; len as usize];
        if stream.read_exact(&mut body).is_err() {
            break;
        }
        let Some(request) = KafkaRequest::parse(&body) else {
            break;
        };
        let response = kafka_binary_response(&request, Arc::clone(&state), log_path);
        let mut framed = Vec::with_capacity(4 + response.len());
        kafka_push_i32(&mut framed, response.len() as i32);
        framed.extend_from_slice(&response);
        if stream.write_all(&framed).is_err() {
            break;
        }
    }
}

#[derive(Debug)]
struct KafkaRequest<'a> {
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    body: &'a [u8],
}

impl<'a> KafkaRequest<'a> {
    fn parse(input: &'a [u8]) -> Option<Self> {
        let mut reader = KafkaReader::new(input);
        let api_key = reader.i16()?;
        let api_version = reader.i16()?;
        let correlation_id = reader.i32()?;
        let _client_id = reader.nullable_string()?;
        if kafka_api_uses_flexible_header(api_key, api_version) {
            reader.tagged_fields()?;
        }
        Some(Self {
            api_key,
            api_version,
            correlation_id,
            body: &input[reader.pos..],
        })
    }
}

fn kafka_api_uses_flexible_header(api_key: i16, version: i16) -> bool {
    matches!(api_key, KAFKA_API_API_VERSIONS if version >= 3)
}

fn kafka_binary_response(
    req: &KafkaRequest<'_>,
    state: Arc<Mutex<KafkaState>>,
    log_path: &Path,
) -> Vec<u8> {
    let mut out = Vec::new();
    kafka_push_i32(&mut out, req.correlation_id);
    if kafka_api_uses_flexible_header(req.api_key, req.api_version) {
        kafka_push_unsigned_varint(&mut out, 0);
    }
    let body = match req.api_key {
        KAFKA_API_API_VERSIONS => kafka_api_versions_response(req.api_version),
        KAFKA_API_METADATA => kafka_metadata_response(req.api_version, req.body, &state),
        KAFKA_API_PRODUCE => kafka_produce_response(req.api_version, req.body, &state, log_path),
        KAFKA_API_FETCH => kafka_fetch_response(req.api_version, req.body, &state, log_path),
        KAFKA_API_LIST_OFFSETS => kafka_list_offsets_response(req.api_version, req.body, &state),
        KAFKA_API_FIND_COORDINATOR => kafka_find_coordinator_response(req.api_version),
        KAFKA_API_OFFSET_COMMIT => kafka_offset_commit_response(req.api_version, req.body),
        KAFKA_API_OFFSET_FETCH => kafka_offset_fetch_response(req.api_version, req.body),
        KAFKA_API_JOIN_GROUP => kafka_join_group_response(req.api_version),
        KAFKA_API_SYNC_GROUP => kafka_sync_group_response(req.api_version),
        KAFKA_API_HEARTBEAT => kafka_errorless_group_response(req.api_version),
        KAFKA_API_LEAVE_GROUP => kafka_errorless_group_response(req.api_version),
        _ => kafka_error_response(35),
    };
    out.extend_from_slice(&body);
    out
}

fn kafka_api_versions_response(version: i16) -> Vec<u8> {
    let apis = [
        (KAFKA_API_PRODUCE, 0, 2),
        (KAFKA_API_FETCH, 0, 2),
        (KAFKA_API_LIST_OFFSETS, 0, 1),
        (KAFKA_API_METADATA, 0, 1),
        (KAFKA_API_OFFSET_COMMIT, 0, 2),
        (KAFKA_API_OFFSET_FETCH, 0, 1),
        (KAFKA_API_FIND_COORDINATOR, 0, 1),
        (KAFKA_API_JOIN_GROUP, 0, 1),
        (KAFKA_API_HEARTBEAT, 0, 0),
        (KAFKA_API_LEAVE_GROUP, 0, 0),
        (KAFKA_API_SYNC_GROUP, 0, 0),
        (KAFKA_API_API_VERSIONS, 0, 3),
    ];
    let mut out = Vec::new();
    kafka_push_i16(&mut out, 0);
    if version >= 3 {
        kafka_push_compact_array_len(&mut out, apis.len());
        for (api, min, max) in apis {
            kafka_push_i16(&mut out, api);
            kafka_push_i16(&mut out, min);
            kafka_push_i16(&mut out, max);
            kafka_push_unsigned_varint(&mut out, 0);
        }
        kafka_push_i32(&mut out, 0);
        kafka_push_unsigned_varint(&mut out, 0);
    } else {
        kafka_push_i32(&mut out, apis.len() as i32);
        for (api, min, max) in apis {
            kafka_push_i16(&mut out, api);
            kafka_push_i16(&mut out, min);
            kafka_push_i16(&mut out, max);
        }
        if version >= 1 {
            kafka_push_i32(&mut out, 0);
        }
    }
    out
}

fn kafka_metadata_response(version: i16, body: &[u8], state: &Arc<Mutex<KafkaState>>) -> Vec<u8> {
    let mut topics = kafka_metadata_topics(body);
    if topics.is_empty()
        && let Ok(guard) = state.lock()
    {
        topics.extend(guard.topics.keys().cloned());
    }
    if topics.is_empty() {
        topics.push("nyx".to_owned());
    }
    topics.sort();
    topics.dedup();

    let mut out = Vec::new();
    kafka_push_i32(&mut out, 1);
    kafka_push_i32(&mut out, 0);
    kafka_push_string(&mut out, "127.0.0.1");
    kafka_push_i32(&mut out, 0);
    if version >= 1 {
        kafka_push_nullable_string(&mut out, None);
        kafka_push_i32(&mut out, 0);
    }
    kafka_push_i32(&mut out, topics.len() as i32);
    for topic in topics {
        kafka_push_i16(&mut out, 0);
        kafka_push_string(&mut out, &topic);
        if version >= 1 {
            out.push(0);
        }
        kafka_push_i32(&mut out, 1);
        kafka_push_i16(&mut out, 0);
        kafka_push_i32(&mut out, 0);
        kafka_push_i32(&mut out, 0);
        kafka_push_i32(&mut out, 1);
        kafka_push_i32(&mut out, 0);
        kafka_push_i32(&mut out, 1);
        kafka_push_i32(&mut out, 0);
    }
    out
}

fn kafka_metadata_topics(body: &[u8]) -> Vec<String> {
    let mut reader = KafkaReader::new(body);
    let Some(len) = reader.array_len() else {
        return Vec::new();
    };
    if len < 0 {
        return Vec::new();
    }
    let mut topics = Vec::new();
    for _ in 0..len.min(256) {
        let Some(topic) = reader.string() else {
            break;
        };
        topics.push(topic);
    }
    topics
}

fn kafka_produce_response(
    version: i16,
    body: &[u8],
    state: &Arc<Mutex<KafkaState>>,
    log_path: &Path,
) -> Vec<u8> {
    let produced = kafka_parse_produce_request(version, body);
    let mut response_topics = BTreeMap::<String, Vec<(i32, i64)>>::new();
    if let Ok(mut guard) = state.lock() {
        for (topic, partition, value) in produced {
            let offset = guard.next_offsets.entry(topic.clone()).or_insert(0);
            let message = KafkaMessage {
                offset: *offset,
                value,
            };
            *offset += 1;
            guard
                .topics
                .entry(topic.clone())
                .or_default()
                .push_back(message.clone());
            let _ = append_broker_event(log_path, "publish", &topic, &message.value);
            response_topics
                .entry(topic)
                .or_default()
                .push((partition, message.offset as i64));
        }
    }
    if response_topics.is_empty() {
        response_topics.insert("nyx".to_owned(), vec![(0, 0)]);
    }

    let mut out = Vec::new();
    kafka_push_i32(&mut out, response_topics.len() as i32);
    for (topic, partitions) in response_topics {
        kafka_push_string(&mut out, &topic);
        kafka_push_i32(&mut out, partitions.len() as i32);
        for (partition, offset) in partitions {
            kafka_push_i32(&mut out, partition);
            kafka_push_i16(&mut out, 0);
            kafka_push_i64(&mut out, offset);
            if version >= 2 {
                kafka_push_i64(&mut out, -1);
            }
        }
    }
    if version >= 1 {
        kafka_push_i32(&mut out, 0);
    }
    out
}

fn kafka_parse_produce_request(version: i16, body: &[u8]) -> Vec<(String, i32, String)> {
    let mut reader = KafkaReader::new(body);
    if version >= 3 {
        let _ = reader.nullable_string();
    }
    let _acks = reader.i16();
    let _timeout = reader.i32();
    let Some(topic_len) = reader.array_len() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for _ in 0..topic_len.clamp(0, 256) {
        let Some(topic) = reader.string() else {
            break;
        };
        let Some(partition_len) = reader.array_len() else {
            break;
        };
        for _ in 0..partition_len.clamp(0, 256) {
            let Some(partition) = reader.i32() else {
                break;
            };
            let Some(record_set) = reader.bytes() else {
                break;
            };
            for value in kafka_message_set_values(record_set) {
                out.push((topic.clone(), partition, value));
            }
        }
    }
    out
}

fn kafka_fetch_response(
    version: i16,
    body: &[u8],
    state: &Arc<Mutex<KafkaState>>,
    log_path: &Path,
) -> Vec<u8> {
    let requested = kafka_parse_fetch_request(version, body);
    let mut out = Vec::new();
    if version >= 1 {
        kafka_push_i32(&mut out, 0);
    }
    kafka_push_i32(&mut out, requested.len() as i32);
    let guard = state.lock().ok();
    for (topic, partitions) in requested {
        kafka_push_string(&mut out, &topic);
        kafka_push_i32(&mut out, partitions.len() as i32);
        for (partition, fetch_offset) in partitions {
            let messages: Vec<KafkaMessage> = guard
                .as_ref()
                .and_then(|g| g.topics.get(&topic))
                .map(|queue| {
                    queue
                        .iter()
                        .filter(|m| m.offset >= fetch_offset as u64)
                        .take(32)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let high_watermark = guard
                .as_ref()
                .and_then(|g| g.next_offsets.get(&topic).copied())
                .unwrap_or(0) as i64;
            let mut message_set = Vec::new();
            for message in messages {
                kafka_push_message_set_entry(
                    &mut message_set,
                    message.offset,
                    message.value.as_bytes(),
                );
                let _ = append_broker_event(log_path, "deliver", &topic, &message.value);
            }
            kafka_push_i32(&mut out, partition);
            kafka_push_i16(&mut out, 0);
            kafka_push_i64(&mut out, high_watermark);
            kafka_push_bytes(&mut out, &message_set);
        }
    }
    out
}

fn kafka_parse_fetch_request(version: i16, body: &[u8]) -> BTreeMap<String, Vec<(i32, i64)>> {
    let mut reader = KafkaReader::new(body);
    let _replica_id = reader.i32();
    let _max_wait_ms = reader.i32();
    let _min_bytes = reader.i32();
    if version >= 3 {
        let _max_bytes = reader.i32();
    }
    let mut out = BTreeMap::new();
    let Some(topic_len) = reader.array_len() else {
        return out;
    };
    for _ in 0..topic_len.clamp(0, 256) {
        let Some(topic) = reader.string() else {
            break;
        };
        let Some(partition_len) = reader.array_len() else {
            break;
        };
        let mut partitions = Vec::new();
        for _ in 0..partition_len.clamp(0, 256) {
            let Some(partition) = reader.i32() else {
                break;
            };
            let Some(fetch_offset) = reader.i64() else {
                break;
            };
            let _max_bytes = reader.i32();
            partitions.push((partition, fetch_offset));
        }
        out.insert(topic, partitions);
    }
    out
}

fn kafka_list_offsets_response(
    _version: i16,
    body: &[u8],
    state: &Arc<Mutex<KafkaState>>,
) -> Vec<u8> {
    let requested = kafka_parse_list_offsets_request(body);
    let mut out = Vec::new();
    kafka_push_i32(&mut out, requested.len() as i32);
    let guard = state.lock().ok();
    for (topic, partitions) in requested {
        kafka_push_string(&mut out, &topic);
        kafka_push_i32(&mut out, partitions.len() as i32);
        for (partition, timestamp) in partitions {
            let end_offset = guard
                .as_ref()
                .and_then(|g| g.next_offsets.get(&topic).copied())
                .unwrap_or(0) as i64;
            let offset = if timestamp == -1 { end_offset } else { 0 };
            kafka_push_i32(&mut out, partition);
            kafka_push_i16(&mut out, 0);
            kafka_push_i64(&mut out, timestamp);
            kafka_push_i64(&mut out, offset);
        }
    }
    out
}

fn kafka_parse_list_offsets_request(body: &[u8]) -> BTreeMap<String, Vec<(i32, i64)>> {
    let mut reader = KafkaReader::new(body);
    let _replica_id = reader.i32();
    let mut out = BTreeMap::new();
    let Some(topic_len) = reader.array_len() else {
        return out;
    };
    for _ in 0..topic_len.clamp(0, 256) {
        let Some(topic) = reader.string() else {
            break;
        };
        let Some(partition_len) = reader.array_len() else {
            break;
        };
        let mut partitions = Vec::new();
        for _ in 0..partition_len.clamp(0, 256) {
            let Some(partition) = reader.i32() else {
                break;
            };
            let Some(timestamp) = reader.i64() else {
                break;
            };
            partitions.push((partition, timestamp));
        }
        out.insert(topic, partitions);
    }
    out
}

fn kafka_find_coordinator_response(version: i16) -> Vec<u8> {
    let mut out = Vec::new();
    if version >= 1 {
        kafka_push_i32(&mut out, 0);
    }
    kafka_push_i16(&mut out, 0);
    kafka_push_i32(&mut out, 0);
    kafka_push_string(&mut out, "127.0.0.1");
    kafka_push_i32(&mut out, 0);
    out
}

fn kafka_offset_commit_response(_version: i16, body: &[u8]) -> Vec<u8> {
    let mut reader = KafkaReader::new(body);
    let _group = reader.string();
    let mut out = Vec::new();
    let topic_len = reader.array_len().unwrap_or(0).max(0);
    kafka_push_i32(&mut out, topic_len);
    for _ in 0..topic_len.min(256) {
        let topic = reader.string().unwrap_or_else(|| "nyx".to_owned());
        kafka_push_string(&mut out, &topic);
        let partition_len = reader.array_len().unwrap_or(0).max(0);
        kafka_push_i32(&mut out, partition_len);
        for _ in 0..partition_len.min(256) {
            let partition = reader.i32().unwrap_or(0);
            let _offset = reader.i64();
            let _metadata = reader.string();
            kafka_push_i32(&mut out, partition);
            kafka_push_i16(&mut out, 0);
        }
    }
    out
}

fn kafka_offset_fetch_response(_version: i16, body: &[u8]) -> Vec<u8> {
    let mut reader = KafkaReader::new(body);
    let _group = reader.string();
    let topic_len = reader.array_len().unwrap_or(0).max(0);
    let mut out = Vec::new();
    kafka_push_i32(&mut out, topic_len);
    for _ in 0..topic_len.min(256) {
        let topic = reader.string().unwrap_or_else(|| "nyx".to_owned());
        kafka_push_string(&mut out, &topic);
        let partition_len = reader.array_len().unwrap_or(0).max(0);
        kafka_push_i32(&mut out, partition_len);
        for _ in 0..partition_len.min(256) {
            let partition = reader.i32().unwrap_or(0);
            kafka_push_i32(&mut out, partition);
            kafka_push_i64(&mut out, -1);
            kafka_push_string(&mut out, "");
            kafka_push_i16(&mut out, 0);
        }
    }
    out
}

fn kafka_join_group_response(_version: i16) -> Vec<u8> {
    let mut out = Vec::new();
    kafka_push_i16(&mut out, 0);
    kafka_push_i32(&mut out, 1);
    kafka_push_string(&mut out, "range");
    kafka_push_string(&mut out, "nyx-member");
    kafka_push_string(&mut out, "nyx-member");
    kafka_push_i32(&mut out, 0);
    out
}

fn kafka_sync_group_response(_version: i16) -> Vec<u8> {
    let mut out = Vec::new();
    kafka_push_i16(&mut out, 0);
    kafka_push_bytes(&mut out, &[]);
    out
}

fn kafka_errorless_group_response(_version: i16) -> Vec<u8> {
    let mut out = Vec::new();
    kafka_push_i16(&mut out, 0);
    out
}

fn kafka_error_response(error_code: i16) -> Vec<u8> {
    let mut out = Vec::new();
    kafka_push_i16(&mut out, error_code);
    out
}

fn kafka_message_set_values(mut input: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while input.len() >= 12 {
        let mut reader = KafkaReader::new(input);
        let _offset = reader.i64();
        let Some(size) = reader.i32() else {
            break;
        };
        if size < 0 || reader.pos + size as usize > input.len() {
            break;
        }
        let message = &input[reader.pos..reader.pos + size as usize];
        if let Some(value) = kafka_message_value(message) {
            out.push(value);
        }
        input = &input[reader.pos + size as usize..];
    }
    out
}

fn kafka_message_value(message: &[u8]) -> Option<String> {
    let mut reader = KafkaReader::new(message);
    let _crc = reader.i32()?;
    let magic = reader.u8()?;
    let _attributes = reader.u8()?;
    if magic == 1 {
        let _timestamp = reader.i64()?;
    }
    let _key = reader.bytes()?;
    let value = reader.bytes()?;
    Some(String::from_utf8_lossy(value).into_owned())
}

fn kafka_push_message_set_entry(out: &mut Vec<u8>, offset: u64, value: &[u8]) {
    let mut message = Vec::new();
    message.extend_from_slice(&[0, 0, 0, 0]);
    message.push(1);
    message.push(0);
    kafka_push_i64(&mut message, 0);
    kafka_push_i32(&mut message, -1);
    kafka_push_i32(&mut message, value.len() as i32);
    message.extend_from_slice(value);
    let crc = crc32_ieee(&message[4..]);
    message[0..4].copy_from_slice(&crc.to_be_bytes());
    kafka_push_i64(out, offset as i64);
    kafka_push_i32(out, message.len() as i32);
    out.extend_from_slice(&message);
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[derive(Debug)]
struct KafkaReader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> KafkaReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let bytes = self.input.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn i16(&mut self) -> Option<i16> {
        Some(i16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn array_len(&mut self) -> Option<i32> {
        self.i32()
    }

    fn string(&mut self) -> Option<String> {
        let len = self.i16()?;
        if len < 0 {
            return None;
        }
        Some(String::from_utf8_lossy(self.take(len as usize)?).into_owned())
    }

    fn nullable_string(&mut self) -> Option<Option<String>> {
        let len = self.i16()?;
        if len < 0 {
            return Some(None);
        }
        Some(Some(
            String::from_utf8_lossy(self.take(len as usize)?).into_owned(),
        ))
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.i32()?;
        if len < 0 {
            return Some(&[]);
        }
        self.take(len as usize)
    }

    fn unsigned_varint(&mut self) -> Option<u32> {
        let mut value = 0_u32;
        let mut shift = 0;
        loop {
            let byte = self.u8()?;
            value |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift > 28 {
                return None;
            }
        }
    }

    fn tagged_fields(&mut self) -> Option<()> {
        let fields = self.unsigned_varint()?;
        for _ in 0..fields.min(1024) {
            let _tag = self.unsigned_varint()?;
            let len = self.unsigned_varint()? as usize;
            let _ = self.take(len)?;
        }
        Some(())
    }
}

fn kafka_push_i16(out: &mut Vec<u8>, value: i16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn kafka_push_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn kafka_push_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn kafka_push_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    kafka_push_i16(out, bytes.len().min(i16::MAX as usize) as i16);
    out.extend_from_slice(&bytes[..bytes.len().min(i16::MAX as usize)]);
}

fn kafka_push_nullable_string(out: &mut Vec<u8>, value: Option<&str>) {
    if let Some(value) = value {
        kafka_push_string(out, value);
    } else {
        kafka_push_i16(out, -1);
    }
}

fn kafka_push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    kafka_push_i32(out, value.len() as i32);
    out.extend_from_slice(value);
}

fn kafka_push_unsigned_varint(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn kafka_push_compact_array_len(out: &mut Vec<u8>, len: usize) {
    kafka_push_unsigned_varint(out, len.saturating_add(1) as u32);
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

#[derive(Debug)]
struct PubsubGrpcListener {
    port: u16,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct PubsubGrpcQueuedMessage {
    ack_id: String,
    message_id: String,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct PubsubGrpcState {
    topics: BTreeSet<String>,
    subscriptions: BTreeMap<String, String>,
    queues: BTreeMap<String, VecDeque<PubsubGrpcQueuedMessage>>,
    inflight: BTreeMap<String, (String, PubsubGrpcQueuedMessage)>,
    next_id: u64,
}

fn start_pubsub_grpc_listener(log_path: PathBuf) -> std::io::Result<Option<PubsubGrpcListener>> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(e) => return Err(e),
    };
    let port = listener.local_addr()?.port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(PubsubGrpcState::default()));
    let shutdown_clone = Arc::clone(&shutdown);
    let state_clone = Arc::clone(&state);
    std::thread::spawn(move || {
        pubsub_grpc_accept_loop(listener, shutdown_clone, state_clone, log_path)
    });
    Ok(Some(PubsubGrpcListener { port, shutdown }))
}

fn pubsub_grpc_accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    state: Arc<Mutex<PubsubGrpcState>>,
    log_path: PathBuf,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let state = Arc::clone(&state);
        let log_path = log_path.clone();
        std::thread::spawn(move || {
            if stream.set_nonblocking(true).is_err() {
                return;
            }
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let Ok(stream) = tokio::net::TcpStream::from_std(stream) else {
                    return;
                };
                handle_pubsub_grpc_connection(stream, state, log_path).await;
            });
        });
    }
}

async fn handle_pubsub_grpc_connection(
    stream: tokio::net::TcpStream,
    state: Arc<Mutex<PubsubGrpcState>>,
    log_path: PathBuf,
) {
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(request) = connection.accept().await {
        let Ok((request, respond)) = request else {
            break;
        };
        let path = request.uri().path().to_owned();
        let body = request.into_body();
        if path.ends_with("/StreamingPull") {
            handle_pubsub_streaming_pull(body, respond, Arc::clone(&state), &log_path).await;
        } else {
            let body = pubsub_grpc_read_all(body).await;
            handle_pubsub_unary(&path, &body, respond, Arc::clone(&state), &log_path).await;
        }
    }
}

async fn pubsub_grpc_read_all(mut body: h2::RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(bytes) = chunk else {
            break;
        };
        let len = bytes.len();
        out.extend_from_slice(&bytes);
        let _ = body.flow_control().release_capacity(len);
    }
    out
}

async fn pubsub_grpc_read_one_message(mut body: h2::RecvStream) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    while out.len() < 5 || out.len() < 5 + u32::from_be_bytes(out[1..5].try_into().ok()?) as usize {
        let bytes = body.data().await?.ok()?;
        let len = bytes.len();
        out.extend_from_slice(&bytes);
        let _ = body.flow_control().release_capacity(len);
    }
    pubsub_grpc_unframe(&out)
}

async fn handle_pubsub_unary(
    path: &str,
    framed_body: &[u8],
    respond: h2::server::SendResponse<bytes::Bytes>,
    state: Arc<Mutex<PubsubGrpcState>>,
    log_path: &Path,
) {
    let payload = pubsub_grpc_unframe(framed_body).unwrap_or_default();
    match path {
        "/google.pubsub.v1.Publisher/CreateTopic" => {
            let topic = PubsubTopic::decode(payload.as_slice()).unwrap_or_default();
            if let Ok(mut guard) = state.lock() {
                guard.topics.insert(topic.name.clone());
            }
            pubsub_send_grpc_message(respond, &topic).await;
        }
        "/google.pubsub.v1.Publisher/GetTopic" => {
            let req = PubsubGetTopicRequest::decode(payload.as_slice()).unwrap_or_default();
            let topic = PubsubTopic { name: req.topic };
            if let Ok(mut guard) = state.lock() {
                guard.topics.insert(topic.name.clone());
            }
            pubsub_send_grpc_message(respond, &topic).await;
        }
        "/google.pubsub.v1.Publisher/Publish" => {
            let req = PubsubPublishRequest::decode(payload.as_slice()).unwrap_or_default();
            let response = pubsub_publish(&state, log_path, req);
            pubsub_send_grpc_message(respond, &response).await;
        }
        "/google.pubsub.v1.Subscriber/CreateSubscription" => {
            let sub = PubsubSubscription::decode(payload.as_slice()).unwrap_or_default();
            if let Ok(mut guard) = state.lock() {
                guard.topics.insert(sub.topic.clone());
                guard
                    .subscriptions
                    .insert(sub.name.clone(), sub.topic.clone());
                guard.queues.entry(sub.name.clone()).or_default();
            }
            pubsub_send_grpc_message(respond, &sub).await;
        }
        "/google.pubsub.v1.Subscriber/Pull" => {
            let req = PubsubPullRequest::decode(payload.as_slice()).unwrap_or_default();
            let response = pubsub_pull(&state, log_path, &req.subscription, req.max_messages);
            pubsub_send_grpc_message(respond, &response).await;
        }
        "/google.pubsub.v1.Subscriber/Acknowledge" => {
            let req = PubsubAcknowledgeRequest::decode(payload.as_slice()).unwrap_or_default();
            pubsub_ack(&state, log_path, &req.subscription, &req.ack_ids);
            pubsub_send_grpc_message(respond, &PubsubEmpty::default()).await;
        }
        _ => pubsub_send_grpc_status(respond, 12, "unimplemented").await,
    }
}

async fn handle_pubsub_streaming_pull(
    body: h2::RecvStream,
    respond: h2::server::SendResponse<bytes::Bytes>,
    state: Arc<Mutex<PubsubGrpcState>>,
    log_path: &Path,
) {
    let Some(payload) = pubsub_grpc_read_one_message(body).await else {
        pubsub_send_grpc_status(respond, 3, "missing request").await;
        return;
    };
    let req = PubsubStreamingPullRequest::decode(payload.as_slice()).unwrap_or_default();
    if !req.ack_ids.is_empty() {
        pubsub_ack(&state, log_path, &req.subscription, &req.ack_ids);
    }
    let max_messages = if req.max_outstanding_messages > 0 {
        req.max_outstanding_messages.min(i64::from(i32::MAX)) as i32
    } else {
        1
    };
    let pull = pubsub_pull(&state, log_path, &req.subscription, max_messages);
    let response = PubsubStreamingPullResponse {
        received_messages: pull.received_messages,
    };
    pubsub_send_grpc_message(respond, &response).await;
}

fn pubsub_publish(
    state: &Arc<Mutex<PubsubGrpcState>>,
    log_path: &Path,
    req: PubsubPublishRequest,
) -> PubsubPublishResponse {
    let mut ids = Vec::new();
    let Ok(mut guard) = state.lock() else {
        return PubsubPublishResponse { message_ids: ids };
    };
    guard.topics.insert(req.topic.clone());
    let subscriptions: Vec<String> = guard
        .subscriptions
        .iter()
        .filter_map(|(sub, topic)| (topic == &req.topic).then_some(sub.clone()))
        .collect();
    for message in req.messages {
        guard.next_id += 1;
        let id = format!("nyx-{:08}", guard.next_id);
        let ack_id = format!("ack-{}", id);
        ids.push(id.clone());
        let payload = String::from_utf8_lossy(&message.data).into_owned();
        let _ = append_broker_event(log_path, "publish", &req.topic, &payload);
        let queued = PubsubGrpcQueuedMessage {
            ack_id,
            message_id: id,
            data: message.data,
        };
        for sub in &subscriptions {
            guard
                .queues
                .entry(sub.clone())
                .or_default()
                .push_back(queued.clone());
        }
    }
    PubsubPublishResponse { message_ids: ids }
}

fn pubsub_pull(
    state: &Arc<Mutex<PubsubGrpcState>>,
    log_path: &Path,
    subscription: &str,
    max_messages: i32,
) -> PubsubPullResponse {
    let mut received = Vec::new();
    let Ok(mut guard) = state.lock() else {
        return PubsubPullResponse {
            received_messages: received,
        };
    };
    let max_messages = max_messages.clamp(1, 100) as usize;
    for _ in 0..max_messages {
        let Some(message) = guard
            .queues
            .entry(subscription.to_owned())
            .or_default()
            .pop_front()
        else {
            break;
        };
        let payload = String::from_utf8_lossy(&message.data).into_owned();
        let _ = append_broker_event(log_path, "deliver", subscription, &payload);
        guard.inflight.insert(
            message.ack_id.clone(),
            (subscription.to_owned(), message.clone()),
        );
        received.push(PubsubReceivedMessage {
            ack_id: message.ack_id.clone(),
            message: Some(PubsubMessage {
                data: message.data,
                message_id: message.message_id,
                ordering_key: String::new(),
            }),
            delivery_attempt: 1,
        });
    }
    PubsubPullResponse {
        received_messages: received,
    }
}

fn pubsub_ack(
    state: &Arc<Mutex<PubsubGrpcState>>,
    log_path: &Path,
    subscription: &str,
    ack_ids: &[String],
) {
    if let Ok(mut guard) = state.lock() {
        for ack_id in ack_ids {
            if guard.inflight.remove(ack_id).is_some() {
                let _ = append_broker_event(log_path, "ack", subscription, ack_id);
            }
        }
    }
}

async fn pubsub_send_grpc_message<M: prost::Message>(
    respond: h2::server::SendResponse<bytes::Bytes>,
    message: &M,
) {
    let mut payload = Vec::new();
    if message.encode(&mut payload).is_err() {
        pubsub_send_grpc_status(respond, 13, "encode failed").await;
        return;
    }
    pubsub_send_grpc_payload(respond, pubsub_grpc_frame(&payload)).await;
}

async fn pubsub_send_grpc_payload(
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    framed_payload: Vec<u8>,
) {
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    if send
        .send_data(bytes::Bytes::from(framed_payload), false)
        .is_err()
    {
        return;
    }
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    let _ = send.send_trailers(trailers);
}

async fn pubsub_send_grpc_status(
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    code: u16,
    message: &str,
) {
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("grpc-status", code.to_string())
        .header("grpc-message", message)
        .body(())
        .unwrap();
    let _ = respond.send_response(response, true);
}

fn pubsub_grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn pubsub_grpc_unframe(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < 5 || input[0] != 0 {
        return None;
    }
    let len = u32::from_be_bytes(input[1..5].try_into().ok()?) as usize;
    Some(input.get(5..5 + len)?.to_vec())
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubEmpty {}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubTopic {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubGetTopicRequest {
    #[prost(string, tag = "1")]
    topic: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubMessage {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
    #[prost(string, tag = "3")]
    message_id: String,
    #[prost(string, tag = "5")]
    ordering_key: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubPublishRequest {
    #[prost(string, tag = "1")]
    topic: String,
    #[prost(message, repeated, tag = "2")]
    messages: Vec<PubsubMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubPublishResponse {
    #[prost(string, repeated, tag = "1")]
    message_ids: Vec<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubSubscription {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    topic: String,
    #[prost(int32, tag = "5")]
    ack_deadline_seconds: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubPullRequest {
    #[prost(string, tag = "1")]
    subscription: String,
    #[prost(bool, tag = "2")]
    return_immediately: bool,
    #[prost(int32, tag = "3")]
    max_messages: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubReceivedMessage {
    #[prost(string, tag = "1")]
    ack_id: String,
    #[prost(message, optional, tag = "2")]
    message: Option<PubsubMessage>,
    #[prost(int32, tag = "3")]
    delivery_attempt: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubPullResponse {
    #[prost(message, repeated, tag = "1")]
    received_messages: Vec<PubsubReceivedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubAcknowledgeRequest {
    #[prost(string, tag = "1")]
    subscription: String,
    #[prost(string, repeated, tag = "2")]
    ack_ids: Vec<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubStreamingPullRequest {
    #[prost(string, tag = "1")]
    subscription: String,
    #[prost(string, repeated, tag = "2")]
    ack_ids: Vec<String>,
    #[prost(int32, tag = "3")]
    stream_ack_deadline_seconds: i32,
    #[prost(string, tag = "5")]
    client_id: String,
    #[prost(int64, tag = "7")]
    max_outstanding_messages: i64,
    #[prost(int64, tag = "8")]
    max_outstanding_bytes: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PubsubStreamingPullResponse {
    #[prost(message, repeated, tag = "1")]
    received_messages: Vec<PubsubReceivedMessage>,
}

#[derive(Debug)]
struct RabbitAmqpListener {
    port: u16,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct RabbitAmqpState {
    next_delivery_tag: u64,
    next_consumer_tag: u64,
    queues: BTreeMap<String, VecDeque<String>>,
    inflight: BTreeMap<u64, (String, String)>,
    consumers: BTreeMap<String, Vec<RabbitAmqpConsumer>>,
    bindings: BTreeMap<(String, String), Vec<String>>,
}

#[derive(Debug, Clone)]
struct RabbitAmqpConsumer {
    consumer_tag: String,
    channel: u16,
    no_ack: bool,
    writer: Arc<Mutex<TcpStream>>,
}

#[derive(Debug)]
struct AmqpFrame {
    frame_type: u8,
    channel: u16,
    payload: Vec<u8>,
}

const AMQP_FRAME_METHOD: u8 = 1;
const AMQP_FRAME_HEADER: u8 = 2;
const AMQP_FRAME_BODY: u8 = 3;
const AMQP_FRAME_HEARTBEAT: u8 = 8;
const AMQP_FRAME_END: u8 = 0xce;

fn start_rabbit_amqp_listener(log_path: PathBuf) -> std::io::Result<Option<RabbitAmqpListener>> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(e) => return Err(e),
    };
    let port = listener.local_addr()?.port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(RabbitAmqpState::default()));
    let shutdown_clone = Arc::clone(&shutdown);
    let state_clone = Arc::clone(&state);
    std::thread::spawn(move || {
        rabbit_amqp_accept_loop(listener, shutdown_clone, state_clone, log_path)
    });
    Ok(Some(RabbitAmqpListener { port, shutdown }))
}

fn rabbit_amqp_accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    state: Arc<Mutex<RabbitAmqpState>>,
    log_path: PathBuf,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let state = Arc::clone(&state);
        let log_path = log_path.clone();
        std::thread::spawn(move || handle_rabbit_amqp_connection(stream, state, &log_path));
    }
}

fn handle_rabbit_amqp_connection(
    stream: TcpStream,
    state: Arc<Mutex<RabbitAmqpState>>,
    log_path: &Path,
) {
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let consumer_writer = match stream.try_clone() {
        Ok(stream) => Arc::new(Mutex::new(stream)),
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut protocol = [0_u8; 8];
    if reader.read_exact(&mut protocol).is_err() || &protocol != b"AMQP\0\0\x09\x01" {
        return;
    }
    if amqp_write_connection_start(&mut writer).is_err() {
        return;
    }

    let mut owned_consumer_tags = Vec::new();
    let mut confirms_enabled = false;
    let mut next_publish_tag = 0_u64;
    loop {
        let Some(frame) = amqp_read_frame(&mut reader) else {
            break;
        };
        if frame.frame_type == AMQP_FRAME_HEARTBEAT {
            let _ = amqp_write_frame(&mut writer, AMQP_FRAME_HEARTBEAT, 0, &[]);
            continue;
        }
        if frame.frame_type != AMQP_FRAME_METHOD {
            continue;
        }
        let Some((class_id, method_id)) = amqp_method_id(&frame.payload) else {
            break;
        };
        match (class_id, method_id) {
            // connection.start-ok
            (10, 11) => {
                if amqp_write_connection_tune(&mut writer).is_err() {
                    break;
                }
            }
            // connection.tune-ok
            (10, 31) => {}
            // connection.open
            (10, 40) => {
                if amqp_write_connection_open_ok(&mut writer).is_err() {
                    break;
                }
            }
            // connection.close
            (10, 50) => {
                let _ = amqp_write_method(&mut writer, frame.channel, 10, 51, &[]);
                break;
            }
            // channel.open
            (20, 10) => {
                let mut args = Vec::new();
                amqp_push_longstr(&mut args, "");
                if amqp_write_method(&mut writer, frame.channel, 20, 11, &args).is_err() {
                    break;
                }
            }
            // channel.close
            (20, 40) => {
                if amqp_write_method(&mut writer, frame.channel, 20, 41, &[]).is_err() {
                    break;
                }
            }
            // basic.qos
            (60, 10) => {
                if amqp_write_method(&mut writer, frame.channel, 60, 11, &[]).is_err() {
                    break;
                }
            }
            // exchange.declare
            (40, 10) => {
                if let Some(exchange) = amqp_exchange_declare_name(&frame.payload)
                    && let Ok(mut guard) = state.lock()
                {
                    guard.bindings.entry((exchange, String::new())).or_default();
                }
                if amqp_write_method(&mut writer, frame.channel, 40, 11, &[]).is_err() {
                    break;
                }
            }
            // basic.consume
            (60, 20) => {
                let Some((queue, requested_tag, no_ack)) = amqp_basic_consume_args(&frame.payload)
                else {
                    continue;
                };
                let queue = if queue.is_empty() {
                    "default".to_owned()
                } else {
                    queue
                };
                let consumer_tag = if let Ok(mut guard) = state.lock() {
                    let tag = if requested_tag.is_empty() {
                        guard.next_consumer_tag += 1;
                        format!("nyx-consumer-{}", guard.next_consumer_tag)
                    } else {
                        requested_tag
                    };
                    guard
                        .consumers
                        .entry(queue)
                        .or_default()
                        .push(RabbitAmqpConsumer {
                            consumer_tag: tag.clone(),
                            channel: frame.channel,
                            no_ack,
                            writer: Arc::clone(&consumer_writer),
                        });
                    tag
                } else {
                    requested_tag
                };
                owned_consumer_tags.push(consumer_tag.clone());
                if amqp_write_basic_consume_ok(&mut writer, frame.channel, &consumer_tag).is_err() {
                    break;
                }
            }
            // basic.cancel
            (60, 30) => {
                if let Some(consumer_tag) = amqp_basic_cancel_tag(&frame.payload) {
                    rabbit_amqp_remove_consumers(&state, std::slice::from_ref(&consumer_tag));
                    if amqp_write_basic_cancel_ok(&mut writer, frame.channel, &consumer_tag)
                        .is_err()
                    {
                        break;
                    }
                }
            }
            // queue.declare
            (50, 10) => {
                let queue = amqp_queue_declare_name(&frame.payload)
                    .filter(|q| !q.is_empty())
                    .unwrap_or_else(|| "nyx-auto".to_owned());
                let message_count = if let Ok(mut guard) = state.lock() {
                    guard.queues.entry(queue.clone()).or_default().len() as u32
                } else {
                    0
                };
                if amqp_write_queue_declare_ok(&mut writer, frame.channel, &queue, message_count)
                    .is_err()
                {
                    break;
                }
            }
            // queue.bind
            (50, 20) => {
                if let Some((queue, exchange, routing_key)) = amqp_queue_bind_args(&frame.payload)
                    && let Ok(mut guard) = state.lock()
                {
                    guard
                        .bindings
                        .entry((exchange, routing_key))
                        .or_default()
                        .push(queue);
                }
                if amqp_write_method(&mut writer, frame.channel, 50, 21, &[]).is_err() {
                    break;
                }
            }
            // queue.delete
            (50, 40) => {
                let queue = amqp_queue_delete_name(&frame.payload).unwrap_or_default();
                let removed = if let Ok(mut guard) = state.lock() {
                    guard.queues.remove(&queue).map(|q| q.len()).unwrap_or(0) as u32
                } else {
                    0
                };
                if amqp_write_queue_delete_ok(&mut writer, frame.channel, removed).is_err() {
                    break;
                }
            }
            // basic.publish
            (60, 40) => {
                let Some((exchange, routing_key)) = amqp_basic_publish_args(&frame.payload) else {
                    continue;
                };
                let routing_key = if routing_key.is_empty() {
                    "default".to_owned()
                } else {
                    routing_key
                };
                let Some(body) = amqp_read_content_body(&mut reader, frame.channel) else {
                    break;
                };
                let payload = String::from_utf8_lossy(&body).into_owned();
                let _ = append_broker_event(log_path, "publish", &routing_key, &payload);
                let destinations =
                    rabbit_amqp_publish_destinations(&state, &exchange, &routing_key);
                for destination in &destinations {
                    if !rabbit_amqp_deliver_to_consumer(
                        &state,
                        log_path,
                        destination,
                        payload.as_bytes(),
                    ) {
                        rabbit_amqp_enqueue(&state, destination, &payload);
                    }
                }
                if confirms_enabled {
                    next_publish_tag = next_publish_tag.saturating_add(1);
                    if amqp_write_basic_ack(&mut writer, frame.channel, next_publish_tag, false)
                        .is_err()
                    {
                        break;
                    }
                }
            }
            // basic.get
            (60, 70) => {
                let queue = amqp_basic_get_queue(&frame.payload)
                    .filter(|q| !q.is_empty())
                    .unwrap_or_else(|| "default".to_owned());
                let (delivery_tag, payload, remaining) = if let Ok(mut guard) = state.lock() {
                    let body = guard.queues.entry(queue.clone()).or_default().pop_front();
                    if let Some(body) = body {
                        guard.next_delivery_tag += 1;
                        let tag = guard.next_delivery_tag;
                        let remaining = guard.queues.get(&queue).map(VecDeque::len).unwrap_or(0);
                        guard.inflight.insert(tag, (queue.clone(), body.clone()));
                        (Some(tag), Some(body), remaining as u32)
                    } else {
                        (None, None, 0)
                    }
                } else {
                    (None, None, 0)
                };
                if let (Some(tag), Some(payload)) = (delivery_tag, payload) {
                    let _ = append_broker_event(log_path, "deliver", &queue, &payload);
                    if amqp_write_basic_get_ok(
                        &mut writer,
                        frame.channel,
                        tag,
                        &queue,
                        remaining,
                        payload.as_bytes(),
                    )
                    .is_err()
                    {
                        break;
                    }
                } else if amqp_write_basic_get_empty(&mut writer, frame.channel).is_err() {
                    break;
                }
            }
            // basic.ack
            (60, 80) => {
                let Some((delivery_tag, multiple)) = amqp_basic_ack_tag(&frame.payload) else {
                    continue;
                };
                for (queue, tag) in rabbit_amqp_ack_deliveries(&state, delivery_tag, multiple) {
                    let _ = append_broker_event(log_path, "ack", &queue, &tag.to_string());
                }
            }
            // basic.reject
            (60, 90) => {
                let Some((delivery_tag, requeue)) = amqp_basic_reject_args(&frame.payload) else {
                    continue;
                };
                for (queue, tag) in
                    rabbit_amqp_nack_deliveries(&state, delivery_tag, false, requeue)
                {
                    let _ = append_broker_event(log_path, "nack", &queue, &tag.to_string());
                }
            }
            // basic.nack
            (60, 120) => {
                let Some((delivery_tag, multiple, requeue)) = amqp_basic_nack_args(&frame.payload)
                else {
                    continue;
                };
                for (queue, tag) in
                    rabbit_amqp_nack_deliveries(&state, delivery_tag, multiple, requeue)
                {
                    let _ = append_broker_event(log_path, "nack", &queue, &tag.to_string());
                }
            }
            // confirm.select
            (85, 10) => {
                confirms_enabled = true;
                if amqp_write_method(&mut writer, frame.channel, 85, 11, &[]).is_err() {
                    break;
                }
            }
            _ => {}
        }
    }
    rabbit_amqp_remove_consumers(&state, &owned_consumer_tags);
}

fn amqp_read_frame(reader: &mut BufReader<TcpStream>) -> Option<AmqpFrame> {
    let mut header = [0_u8; 7];
    reader.read_exact(&mut header).ok()?;
    let frame_type = header[0];
    let channel = u16::from_be_bytes([header[1], header[2]]);
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    if size > 1024 * 1024 {
        return None;
    }
    let mut payload = vec![0_u8; size];
    if size > 0 {
        reader.read_exact(&mut payload).ok()?;
    }
    let mut end = [0_u8; 1];
    reader.read_exact(&mut end).ok()?;
    if end[0] != AMQP_FRAME_END {
        return None;
    }
    Some(AmqpFrame {
        frame_type,
        channel,
        payload,
    })
}

fn amqp_write_connection_start(writer: &mut TcpStream) -> std::io::Result<()> {
    let mut args = vec![0, 9];
    amqp_push_table_empty(&mut args);
    amqp_push_longstr(&mut args, "PLAIN AMQPLAIN");
    amqp_push_longstr(&mut args, "en_US");
    amqp_write_method(writer, 0, 10, 10, &args)
}

fn amqp_write_connection_tune(writer: &mut TcpStream) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_u16(&mut args, 2047);
    amqp_push_u32(&mut args, 131_072);
    amqp_push_u16(&mut args, 0);
    amqp_write_method(writer, 0, 10, 30, &args)
}

fn amqp_write_connection_open_ok(writer: &mut TcpStream) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_shortstr(&mut args, "");
    amqp_write_method(writer, 0, 10, 41, &args)
}

fn amqp_write_queue_declare_ok(
    writer: &mut TcpStream,
    channel: u16,
    queue: &str,
    message_count: u32,
) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_shortstr(&mut args, queue);
    amqp_push_u32(&mut args, message_count);
    amqp_push_u32(&mut args, 0);
    amqp_write_method(writer, channel, 50, 11, &args)
}

fn amqp_write_queue_delete_ok(
    writer: &mut TcpStream,
    channel: u16,
    message_count: u32,
) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_u32(&mut args, message_count);
    amqp_write_method(writer, channel, 50, 41, &args)
}

fn amqp_write_basic_ack(
    writer: &mut TcpStream,
    channel: u16,
    delivery_tag: u64,
    multiple: bool,
) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_u64(&mut args, delivery_tag);
    args.push(u8::from(multiple));
    amqp_write_method(writer, channel, 60, 80, &args)
}

fn amqp_write_basic_get_ok(
    writer: &mut TcpStream,
    channel: u16,
    delivery_tag: u64,
    routing_key: &str,
    message_count: u32,
    body: &[u8],
) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_u64(&mut args, delivery_tag);
    args.push(0);
    amqp_push_shortstr(&mut args, "");
    amqp_push_shortstr(&mut args, routing_key);
    amqp_push_u32(&mut args, message_count);
    amqp_write_method(writer, channel, 60, 71, &args)?;
    amqp_write_content(writer, channel, body)
}

fn amqp_write_basic_get_empty(writer: &mut TcpStream, channel: u16) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_shortstr(&mut args, "");
    amqp_write_method(writer, channel, 60, 72, &args)
}

fn amqp_write_basic_consume_ok(
    writer: &mut TcpStream,
    channel: u16,
    consumer_tag: &str,
) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_shortstr(&mut args, consumer_tag);
    amqp_write_method(writer, channel, 60, 21, &args)
}

fn amqp_write_basic_cancel_ok(
    writer: &mut TcpStream,
    channel: u16,
    consumer_tag: &str,
) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_shortstr(&mut args, consumer_tag);
    amqp_write_method(writer, channel, 60, 31, &args)
}

fn amqp_write_basic_deliver(
    writer: &mut TcpStream,
    channel: u16,
    consumer_tag: &str,
    delivery_tag: u64,
    routing_key: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let mut args = Vec::new();
    amqp_push_shortstr(&mut args, consumer_tag);
    amqp_push_u64(&mut args, delivery_tag);
    args.push(0);
    amqp_push_shortstr(&mut args, "");
    amqp_push_shortstr(&mut args, routing_key);
    amqp_write_method(writer, channel, 60, 60, &args)?;
    amqp_write_content(writer, channel, body)
}

fn amqp_write_content(writer: &mut TcpStream, channel: u16, body: &[u8]) -> std::io::Result<()> {
    let mut header = Vec::new();
    amqp_push_u16(&mut header, 60);
    amqp_push_u16(&mut header, 0);
    amqp_push_u64(&mut header, body.len() as u64);
    amqp_push_u16(&mut header, 0);
    amqp_write_frame(writer, AMQP_FRAME_HEADER, channel, &header)?;
    amqp_write_frame(writer, AMQP_FRAME_BODY, channel, body)
}

fn amqp_write_method(
    writer: &mut TcpStream,
    channel: u16,
    class_id: u16,
    method_id: u16,
    args: &[u8],
) -> std::io::Result<()> {
    let mut payload = Vec::with_capacity(4 + args.len());
    amqp_push_u16(&mut payload, class_id);
    amqp_push_u16(&mut payload, method_id);
    payload.extend_from_slice(args);
    amqp_write_frame(writer, AMQP_FRAME_METHOD, channel, &payload)
}

fn amqp_write_frame(
    writer: &mut TcpStream,
    frame_type: u8,
    channel: u16,
    payload: &[u8],
) -> std::io::Result<()> {
    writer.write_all(&[frame_type])?;
    writer.write_all(&channel.to_be_bytes())?;
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.write_all(&[AMQP_FRAME_END])
}

fn amqp_read_content_body(reader: &mut BufReader<TcpStream>, channel: u16) -> Option<Vec<u8>> {
    let header = loop {
        let frame = amqp_read_frame(reader)?;
        if frame.frame_type == AMQP_FRAME_HEARTBEAT {
            continue;
        }
        if frame.frame_type == AMQP_FRAME_HEADER && frame.channel == channel {
            break frame;
        }
        return None;
    };
    if header.payload.len() < 12 {
        return None;
    }
    let size = u64::from_be_bytes(header.payload[4..12].try_into().ok()?) as usize;
    if size > 1024 * 1024 {
        return None;
    }
    let mut body = Vec::with_capacity(size);
    while body.len() < size {
        let frame = amqp_read_frame(reader)?;
        if frame.frame_type == AMQP_FRAME_HEARTBEAT {
            continue;
        }
        if frame.frame_type != AMQP_FRAME_BODY || frame.channel != channel {
            return None;
        }
        body.extend_from_slice(&frame.payload);
    }
    body.truncate(size);
    Some(body)
}

fn amqp_method_id(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([payload[0], payload[1]]),
        u16::from_be_bytes([payload[2], payload[3]]),
    ))
}

fn amqp_queue_declare_name(payload: &[u8]) -> Option<String> {
    let mut idx = 4;
    amqp_take_u16(payload, &mut idx)?;
    amqp_take_shortstr(payload, &mut idx)
}

fn amqp_exchange_declare_name(payload: &[u8]) -> Option<String> {
    let mut idx = 4;
    amqp_take_u16(payload, &mut idx)?;
    amqp_take_shortstr(payload, &mut idx)
}

fn amqp_queue_bind_args(payload: &[u8]) -> Option<(String, String, String)> {
    let mut idx = 4;
    amqp_take_u16(payload, &mut idx)?;
    let queue = amqp_take_shortstr(payload, &mut idx)?;
    let exchange = amqp_take_shortstr(payload, &mut idx)?;
    let routing_key = amqp_take_shortstr(payload, &mut idx)?;
    Some((queue, exchange, routing_key))
}

fn amqp_queue_delete_name(payload: &[u8]) -> Option<String> {
    let mut idx = 4;
    amqp_take_u16(payload, &mut idx)?;
    amqp_take_shortstr(payload, &mut idx)
}

fn amqp_basic_publish_args(payload: &[u8]) -> Option<(String, String)> {
    let mut idx = 4;
    amqp_take_u16(payload, &mut idx)?;
    let exchange = amqp_take_shortstr(payload, &mut idx)?;
    let routing_key = amqp_take_shortstr(payload, &mut idx)?;
    Some((exchange, routing_key))
}

fn amqp_basic_get_queue(payload: &[u8]) -> Option<String> {
    let mut idx = 4;
    amqp_take_u16(payload, &mut idx)?;
    amqp_take_shortstr(payload, &mut idx)
}

fn amqp_basic_consume_args(payload: &[u8]) -> Option<(String, String, bool)> {
    let mut idx = 4;
    amqp_take_u16(payload, &mut idx)?;
    let queue = amqp_take_shortstr(payload, &mut idx)?;
    let consumer_tag = amqp_take_shortstr(payload, &mut idx)?;
    let bits = payload.get(idx).copied().unwrap_or(0);
    Some((queue, consumer_tag, bits & 0b0000_0010 != 0))
}

fn amqp_basic_cancel_tag(payload: &[u8]) -> Option<String> {
    let mut idx = 4;
    amqp_take_shortstr(payload, &mut idx)
}

fn amqp_basic_ack_tag(payload: &[u8]) -> Option<(u64, bool)> {
    let mut idx = 4;
    let tag = amqp_take_u64(payload, &mut idx)?;
    let bits = payload.get(idx).copied().unwrap_or(0);
    Some((tag, bits & 1 != 0))
}

fn amqp_basic_reject_args(payload: &[u8]) -> Option<(u64, bool)> {
    let mut idx = 4;
    let tag = amqp_take_u64(payload, &mut idx)?;
    let bits = payload.get(idx).copied().unwrap_or(0);
    Some((tag, bits & 1 != 0))
}

fn amqp_basic_nack_args(payload: &[u8]) -> Option<(u64, bool, bool)> {
    let mut idx = 4;
    let tag = amqp_take_u64(payload, &mut idx)?;
    let bits = payload.get(idx).copied().unwrap_or(0);
    Some((tag, bits & 1 != 0, bits & 0b10 != 0))
}

fn amqp_take_u16(payload: &[u8], idx: &mut usize) -> Option<u16> {
    let end = *idx + 2;
    let bytes: [u8; 2] = payload.get(*idx..end)?.try_into().ok()?;
    *idx = end;
    Some(u16::from_be_bytes(bytes))
}

fn amqp_take_u64(payload: &[u8], idx: &mut usize) -> Option<u64> {
    let end = *idx + 8;
    let bytes: [u8; 8] = payload.get(*idx..end)?.try_into().ok()?;
    *idx = end;
    Some(u64::from_be_bytes(bytes))
}

fn amqp_take_shortstr(payload: &[u8], idx: &mut usize) -> Option<String> {
    let len = *payload.get(*idx)? as usize;
    *idx += 1;
    let end = *idx + len;
    let s = String::from_utf8_lossy(payload.get(*idx..end)?).into_owned();
    *idx = end;
    Some(s)
}

fn amqp_push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn amqp_push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn amqp_push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn amqp_push_shortstr(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len().min(u8::MAX as usize);
    out.push(len as u8);
    out.extend_from_slice(&bytes[..len]);
}

fn amqp_push_longstr(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    amqp_push_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn amqp_push_table_empty(out: &mut Vec<u8>) {
    amqp_push_u32(out, 0);
}

fn rabbit_amqp_deliver_to_consumer(
    state: &Arc<Mutex<RabbitAmqpState>>,
    log_path: &Path,
    queue: &str,
    body: &[u8],
) -> bool {
    let Some((consumer, delivery_tag)) = ({
        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        let consumer = guard
            .consumers
            .get(queue)
            .and_then(|consumers| consumers.first())
            .cloned();
        consumer.map(|consumer| {
            guard.next_delivery_tag += 1;
            let tag = guard.next_delivery_tag;
            if !consumer.no_ack {
                guard.inflight.insert(
                    tag,
                    (queue.to_owned(), String::from_utf8_lossy(body).into_owned()),
                );
            }
            (consumer, tag)
        })
    }) else {
        return false;
    };
    let Ok(mut writer) = consumer.writer.lock() else {
        return false;
    };
    if amqp_write_basic_deliver(
        &mut writer,
        consumer.channel,
        &consumer.consumer_tag,
        delivery_tag,
        queue,
        body,
    )
    .is_ok()
    {
        let payload = String::from_utf8_lossy(body).into_owned();
        let _ = append_broker_event(log_path, "deliver", queue, &payload);
        true
    } else {
        false
    }
}

fn rabbit_amqp_publish_destinations(
    state: &Arc<Mutex<RabbitAmqpState>>,
    exchange: &str,
    routing_key: &str,
) -> Vec<String> {
    if exchange.is_empty() {
        return vec![routing_key.to_owned()];
    }
    let mut out = state
        .lock()
        .ok()
        .and_then(|guard| {
            guard
                .bindings
                .get(&(exchange.to_owned(), routing_key.to_owned()))
                .cloned()
        })
        .unwrap_or_default();
    if out.is_empty() {
        out.push(routing_key.to_owned());
    }
    out.sort();
    out.dedup();
    out
}

fn rabbit_amqp_enqueue(state: &Arc<Mutex<RabbitAmqpState>>, queue: &str, payload: &str) {
    if let Ok(mut guard) = state.lock() {
        guard
            .queues
            .entry(queue.to_owned())
            .or_default()
            .push_back(payload.to_owned());
    }
}

fn rabbit_amqp_ack_deliveries(
    state: &Arc<Mutex<RabbitAmqpState>>,
    delivery_tag: u64,
    multiple: bool,
) -> Vec<(String, u64)> {
    let mut acked = Vec::new();
    if let Ok(mut guard) = state.lock() {
        if multiple {
            let tags: Vec<u64> = guard
                .inflight
                .keys()
                .copied()
                .filter(|tag| *tag <= delivery_tag)
                .collect();
            for tag in tags {
                if let Some((queue, _payload)) = guard.inflight.remove(&tag) {
                    acked.push((queue, tag));
                }
            }
        } else if let Some((queue, _payload)) = guard.inflight.remove(&delivery_tag) {
            acked.push((queue, delivery_tag));
        }
    }
    acked
}

fn rabbit_amqp_nack_deliveries(
    state: &Arc<Mutex<RabbitAmqpState>>,
    delivery_tag: u64,
    multiple: bool,
    requeue: bool,
) -> Vec<(String, u64)> {
    let mut nacked = Vec::new();
    if let Ok(mut guard) = state.lock() {
        let tags: Vec<u64> = if multiple {
            guard
                .inflight
                .keys()
                .copied()
                .filter(|tag| *tag <= delivery_tag)
                .collect()
        } else {
            vec![delivery_tag]
        };
        for tag in tags {
            if let Some((queue, payload)) = guard.inflight.remove(&tag) {
                if requeue {
                    guard
                        .queues
                        .entry(queue.clone())
                        .or_default()
                        .push_front(payload);
                }
                nacked.push((queue, tag));
            }
        }
    }
    nacked
}

fn rabbit_amqp_remove_consumers(state: &Arc<Mutex<RabbitAmqpState>>, consumer_tags: &[String]) {
    if consumer_tags.is_empty() {
        return;
    }
    if let Ok(mut guard) = state.lock() {
        for consumers in guard.consumers.values_mut() {
            consumers.retain(|consumer| !consumer_tags.contains(&consumer.consumer_tag));
        }
    }
}

#[derive(Debug)]
struct NatsListener {
    port: u16,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct NatsSubscriber {
    sid: String,
    writer: Arc<Mutex<TcpStream>>,
}

#[derive(Debug, Default)]
struct NatsState {
    subscribers: BTreeMap<String, Vec<NatsSubscriber>>,
}

fn start_nats_listener(log_path: PathBuf) -> std::io::Result<Option<NatsListener>> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(e) => return Err(e),
    };
    let port = listener.local_addr()?.port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(NatsState::default()));
    let shutdown_clone = Arc::clone(&shutdown);
    let state_clone = Arc::clone(&state);
    std::thread::spawn(move || {
        nats_accept_loop(listener, shutdown_clone, state_clone, log_path, port)
    });
    Ok(Some(NatsListener { port, shutdown }))
}

fn nats_accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    state: Arc<Mutex<NatsState>>,
    log_path: PathBuf,
    port: u16,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let state = Arc::clone(&state);
        let log_path = log_path.clone();
        std::thread::spawn(move || handle_nats_connection(stream, state, &log_path, port));
    }
}

fn handle_nats_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<NatsState>>,
    log_path: &Path,
    port: u16,
) {
    let info = format!(
        concat!(
            "INFO {{",
            r#""server_id":"nyx","#,
            r#""server_name":"nyx-broker-stub","#,
            r#""version":"0.0.0","#,
            r#""proto":1,"#,
            r#""go":"rust","#,
            r#""host":"127.0.0.1","#,
            r#""port":{port},"#,
            r#""headers":false,"#,
            r#""auth_required":false,"#,
            r#""tls_required":false,"#,
            r#""max_payload":1048576"#,
            "}}\r\n"
        ),
        port = port
    );
    if stream.write_all(info.as_bytes()).is_err() {
        return;
    }
    let writer = match stream.try_clone() {
        Ok(stream) => Arc::new(Mutex::new(stream)),
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut owned_sids = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let Ok(n) = reader.read_line(&mut line) else {
            break;
        };
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(command) = parts.next() else {
            continue;
        };
        match command.to_ascii_uppercase().as_str() {
            "CONNECT" => {
                let _ = nats_write(&writer, b"+OK\r\n");
            }
            "PING" => {
                let _ = nats_write(&writer, b"PONG\r\n");
            }
            "PONG" | "+OK" => {}
            "SUB" => {
                let Some(subject) = parts.next() else {
                    let _ = nats_write(&writer, b"-ERR 'missing subject'\r\n");
                    continue;
                };
                let fields: Vec<&str> = parts.collect();
                let Some(sid) = fields.last() else {
                    let _ = nats_write(&writer, b"-ERR 'missing sid'\r\n");
                    continue;
                };
                if let Ok(mut guard) = state.lock() {
                    guard
                        .subscribers
                        .entry(subject.to_owned())
                        .or_default()
                        .push(NatsSubscriber {
                            sid: (*sid).to_owned(),
                            writer: Arc::clone(&writer),
                        });
                    owned_sids.push((*sid).to_owned());
                }
            }
            "UNSUB" => {
                if let Some(sid) = parts.next() {
                    nats_remove_subscription(&state, sid);
                }
            }
            "PUB" => {
                let Some(subject) = parts.next() else {
                    let _ = nats_write(&writer, b"-ERR 'missing subject'\r\n");
                    continue;
                };
                let fields: Vec<&str> = parts.collect();
                let Some(size_str) = fields.last() else {
                    let _ = nats_write(&writer, b"-ERR 'missing size'\r\n");
                    continue;
                };
                let Ok(size) = size_str.parse::<usize>() else {
                    let _ = nats_write(&writer, b"-ERR 'bad size'\r\n");
                    continue;
                };
                if size > 1024 * 1024 {
                    let _ = nats_write(&writer, b"-ERR 'payload too large'\r\n");
                    break;
                }
                let mut payload = vec![0_u8; size];
                if reader.read_exact(&mut payload).is_err() {
                    break;
                }
                let mut crlf = [0_u8; 2];
                if reader.read_exact(&mut crlf).is_err() {
                    break;
                }
                let payload_text = String::from_utf8_lossy(&payload).into_owned();
                let _ = append_broker_event(log_path, "publish", subject, &payload_text);
                nats_deliver(&state, log_path, subject, &payload);
            }
            _ => {
                let _ = nats_write(&writer, b"-ERR 'unknown command'\r\n");
            }
        }
    }
    for sid in owned_sids {
        nats_remove_subscription(&state, &sid);
    }
}

fn nats_write(writer: &Arc<Mutex<TcpStream>>, bytes: &[u8]) -> std::io::Result<()> {
    let mut guard = writer
        .lock()
        .map_err(|_| std::io::Error::other("nats writer poisoned"))?;
    guard.write_all(bytes)
}

fn nats_deliver(state: &Arc<Mutex<NatsState>>, log_path: &Path, subject: &str, payload: &[u8]) {
    let subscribers = state
        .lock()
        .ok()
        .and_then(|guard| guard.subscribers.get(subject).cloned())
        .unwrap_or_default();
    let payload_text = String::from_utf8_lossy(payload).into_owned();
    for subscriber in subscribers {
        let header = format!("MSG {subject} {} {}\r\n", subscriber.sid, payload.len());
        if nats_write(&subscriber.writer, header.as_bytes())
            .and_then(|_| nats_write(&subscriber.writer, payload))
            .and_then(|_| nats_write(&subscriber.writer, b"\r\n"))
            .is_ok()
        {
            let _ = append_broker_event(log_path, "deliver", subject, &payload_text);
        }
    }
}

fn nats_remove_subscription(state: &Arc<Mutex<NatsState>>, sid: &str) {
    if let Ok(mut guard) = state.lock() {
        for subscribers in guard.subscribers.values_mut() {
            subscribers.retain(|subscriber| subscriber.sid != sid);
        }
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
            endpoint == "loopback://kafka" || endpoint.starts_with("kafka://127.0.0.1:"),
            "Kafka endpoint should be loopback fallback or Kafka protocol endpoint, got {endpoint}"
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
    fn kafka_broker_exposes_protocol_endpoint() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Kafka, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://kafka" {
            return;
        }
        assert!(
            endpoint.starts_with("kafka://127.0.0.1:"),
            "Kafka endpoint should be a protocol-compatible endpoint, got {endpoint}"
        );
    }

    #[test]
    fn pubsub_broker_exposes_grpc_endpoint() {
        for kind in [StubKind::Pubsub] {
            let dir = TempDir::new().unwrap();
            let stub = BrokerStub::start(kind, dir.path()).unwrap();
            let endpoint = stub.endpoint();
            if endpoint == format!("loopback://{}", kind.tag()) {
                continue;
            }
            assert!(
                endpoint.starts_with("pubsub://127.0.0.1:"),
                "{kind:?} endpoint should be a protocol-compatible gRPC endpoint, got {endpoint}"
            );
        }
    }

    #[test]
    fn rabbit_broker_exposes_amqp_endpoint() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Rabbit, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://rabbit" {
            return;
        }
        assert!(
            endpoint.starts_with("amqp://127.0.0.1:"),
            "Rabbit endpoint should be a protocol-compatible AMQP endpoint, got {endpoint}"
        );
    }

    #[test]
    fn nats_broker_exposes_protocol_endpoint() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Nats, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://nats" {
            return;
        }
        assert!(
            endpoint.starts_with("nats://127.0.0.1:"),
            "NATS endpoint should be a protocol-compatible endpoint, got {endpoint}"
        );
    }

    #[test]
    fn kafka_protocol_server_records_publish_deliver() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Kafka, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://kafka" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("kafka://127.0.0.1:")
            .parse()
            .unwrap();
        let api_versions = kafka_roundtrip(port, kafka_test_request(18, 3, 1, &[]));
        let mut api_reader = KafkaReader::new(&api_versions);
        assert_eq!(api_reader.i32(), Some(1));
        assert!(api_versions.len() > 8, "{api_versions:?}");

        let mut metadata_body = Vec::new();
        kafka_push_i32(&mut metadata_body, 1);
        kafka_push_string(&mut metadata_body, "orders");
        let metadata = kafka_roundtrip(port, kafka_test_request(3, 1, 2, &metadata_body));
        let mut metadata_reader = KafkaReader::new(&metadata);
        assert_eq!(metadata_reader.i32(), Some(2));
        assert!(metadata.windows("orders".len()).any(|w| w == b"orders"));

        let mut message_set = Vec::new();
        kafka_push_message_set_entry(&mut message_set, 0, b"NYX\tPAYLOAD");
        let mut produce_body = Vec::new();
        kafka_push_i16(&mut produce_body, 1);
        kafka_push_i32(&mut produce_body, 1000);
        kafka_push_i32(&mut produce_body, 1);
        kafka_push_string(&mut produce_body, "orders");
        kafka_push_i32(&mut produce_body, 1);
        kafka_push_i32(&mut produce_body, 0);
        kafka_push_bytes(&mut produce_body, &message_set);
        let produce = kafka_roundtrip(port, kafka_test_request(0, 2, 3, &produce_body));
        assert_eq!(&produce[..4], &3_i32.to_be_bytes());

        let mut fetch_body = Vec::new();
        kafka_push_i32(&mut fetch_body, -1);
        kafka_push_i32(&mut fetch_body, 100);
        kafka_push_i32(&mut fetch_body, 1);
        kafka_push_i32(&mut fetch_body, 1);
        kafka_push_string(&mut fetch_body, "orders");
        kafka_push_i32(&mut fetch_body, 1);
        kafka_push_i32(&mut fetch_body, 0);
        kafka_push_i64(&mut fetch_body, 0);
        kafka_push_i32(&mut fetch_body, 1024 * 1024);
        let fetch = kafka_roundtrip(port, kafka_test_request(1, 2, 4, &fetch_body));
        let fetched_values = kafka_test_fetch_values(&fetch);
        assert_eq!(fetched_values, vec!["NYX\tPAYLOAD".to_owned()]);

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(actions, vec!["publish", "deliver"]);
        assert_eq!(events[0].detail.get("destination").unwrap(), "orders");
        assert_eq!(events[1].detail.get("payload").unwrap(), "NYX\tPAYLOAD");
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
    fn pubsub_grpc_emulator_records_publish_deliver_ack() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Pubsub, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://pubsub" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("pubsub://127.0.0.1:")
            .parse()
            .unwrap();
        let topic = "projects/nyx/topics/orders";
        let subscription = "projects/nyx/subscriptions/orders-sub";

        let created_topic: PubsubTopic = pubsub_grpc_unary(
            port,
            "/google.pubsub.v1.Publisher/CreateTopic",
            &PubsubTopic {
                name: topic.to_owned(),
            },
        );
        assert_eq!(created_topic.name, topic);

        let created_subscription: PubsubSubscription = pubsub_grpc_unary(
            port,
            "/google.pubsub.v1.Subscriber/CreateSubscription",
            &PubsubSubscription {
                name: subscription.to_owned(),
                topic: topic.to_owned(),
                ack_deadline_seconds: 10,
            },
        );
        assert_eq!(created_subscription.name, subscription);

        let published: PubsubPublishResponse = pubsub_grpc_unary(
            port,
            "/google.pubsub.v1.Publisher/Publish",
            &PubsubPublishRequest {
                topic: topic.to_owned(),
                messages: vec![PubsubMessage {
                    data: b"NYX\tPAYLOAD".to_vec(),
                    message_id: String::new(),
                    ordering_key: String::new(),
                }],
            },
        );
        assert_eq!(published.message_ids, vec!["nyx-00000001"]);

        let pulled: PubsubPullResponse = pubsub_grpc_unary(
            port,
            "/google.pubsub.v1.Subscriber/Pull",
            &PubsubPullRequest {
                subscription: subscription.to_owned(),
                return_immediately: true,
                max_messages: 1,
            },
        );
        assert_eq!(pulled.received_messages.len(), 1);
        let received = &pulled.received_messages[0];
        assert_eq!(
            received.message.as_ref().unwrap().data,
            b"NYX\tPAYLOAD".to_vec()
        );

        let _empty: PubsubEmpty = pubsub_grpc_unary(
            port,
            "/google.pubsub.v1.Subscriber/Acknowledge",
            &PubsubAcknowledgeRequest {
                subscription: subscription.to_owned(),
                ack_ids: vec![received.ack_id.clone()],
            },
        );

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(actions, vec!["publish", "deliver", "ack"]);
        assert_eq!(events[0].detail.get("destination").unwrap(), topic);
        assert_eq!(events[1].detail.get("payload").unwrap(), "NYX\tPAYLOAD");
        assert_eq!(events[2].detail.get("payload").unwrap(), &received.ack_id);
    }

    #[test]
    fn rabbit_amqp_protocol_server_records_publish_deliver_ack() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Rabbit, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://rabbit" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("amqp://127.0.0.1:")
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let mut reader = BufReader::new(s.try_clone().unwrap());
        s.write_all(b"AMQP\0\0\x09\x01").unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 0, 10, 10);

        let mut start_ok = Vec::new();
        amqp_push_table_empty(&mut start_ok);
        amqp_push_shortstr(&mut start_ok, "PLAIN");
        amqp_push_longstr(&mut start_ok, "\0guest\0guest");
        amqp_push_shortstr(&mut start_ok, "en_US");
        amqp_write_method(&mut s, 0, 10, 11, &start_ok).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 0, 10, 30);

        let mut tune_ok = Vec::new();
        amqp_push_u16(&mut tune_ok, 2047);
        amqp_push_u32(&mut tune_ok, 131_072);
        amqp_push_u16(&mut tune_ok, 0);
        amqp_write_method(&mut s, 0, 10, 31, &tune_ok).unwrap();

        let mut open = Vec::new();
        amqp_push_shortstr(&mut open, "/");
        amqp_push_shortstr(&mut open, "");
        open.push(0);
        amqp_write_method(&mut s, 0, 10, 40, &open).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 0, 10, 41);

        let mut channel_open = Vec::new();
        amqp_push_longstr(&mut channel_open, "");
        amqp_write_method(&mut s, 1, 20, 10, &channel_open).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 20, 11);

        let mut declare = Vec::new();
        amqp_push_u16(&mut declare, 0);
        amqp_push_shortstr(&mut declare, "work");
        declare.push(0);
        amqp_push_table_empty(&mut declare);
        amqp_write_method(&mut s, 1, 50, 10, &declare).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 50, 11);

        let mut publish = Vec::new();
        amqp_push_u16(&mut publish, 0);
        amqp_push_shortstr(&mut publish, "");
        amqp_push_shortstr(&mut publish, "work");
        publish.push(0);
        amqp_write_method(&mut s, 1, 60, 40, &publish).unwrap();
        amqp_write_content(&mut s, 1, b"NYX\tPAYLOAD").unwrap();

        let mut get = Vec::new();
        amqp_push_u16(&mut get, 0);
        amqp_push_shortstr(&mut get, "work");
        get.push(0);
        amqp_write_method(&mut s, 1, 60, 70, &get).unwrap();
        let get_ok = amqp_read_frame(&mut reader).unwrap();
        assert_amqp_method_ref(&get_ok, 1, 60, 71);
        let mut idx = 4;
        let delivery_tag = amqp_take_u64(&get_ok.payload, &mut idx).unwrap();
        let header = amqp_read_frame(&mut reader).unwrap();
        assert_eq!(header.frame_type, AMQP_FRAME_HEADER);
        let body = amqp_read_frame(&mut reader).unwrap();
        assert_eq!(body.frame_type, AMQP_FRAME_BODY);
        assert_eq!(body.payload, b"NYX\tPAYLOAD");

        let mut ack = Vec::new();
        amqp_push_u64(&mut ack, delivery_tag);
        ack.push(0);
        amqp_write_method(&mut s, 1, 60, 80, &ack).unwrap();
        std::thread::sleep(Duration::from_millis(25));

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(actions, vec!["publish", "deliver", "ack"]);
        assert_eq!(events[0].detail.get("destination").unwrap(), "work");
        assert_eq!(events[1].detail.get("payload").unwrap(), "NYX\tPAYLOAD");
        assert_eq!(
            events[2].detail.get("payload").unwrap(),
            &delivery_tag.to_string()
        );
    }

    #[test]
    fn rabbit_amqp_basic_consume_receives_published_messages() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Rabbit, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://rabbit" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("amqp://127.0.0.1:")
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let mut reader = BufReader::new(s.try_clone().unwrap());
        amqp_test_open_channel(&mut s, &mut reader);

        let mut declare = Vec::new();
        amqp_push_u16(&mut declare, 0);
        amqp_push_shortstr(&mut declare, "work");
        declare.push(0);
        amqp_push_table_empty(&mut declare);
        amqp_write_method(&mut s, 1, 50, 10, &declare).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 50, 11);

        let mut consume = Vec::new();
        amqp_push_u16(&mut consume, 0);
        amqp_push_shortstr(&mut consume, "work");
        amqp_push_shortstr(&mut consume, "ctag");
        consume.push(0);
        amqp_push_table_empty(&mut consume);
        amqp_write_method(&mut s, 1, 60, 20, &consume).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 60, 21);

        let mut publish = Vec::new();
        amqp_push_u16(&mut publish, 0);
        amqp_push_shortstr(&mut publish, "");
        amqp_push_shortstr(&mut publish, "work");
        publish.push(0);
        amqp_write_method(&mut s, 1, 60, 40, &publish).unwrap();
        amqp_write_content(&mut s, 1, b"async payload").unwrap();

        let deliver = amqp_read_frame(&mut reader).unwrap();
        assert_amqp_method_ref(&deliver, 1, 60, 60);
        let mut idx = 4;
        assert_eq!(
            amqp_take_shortstr(&deliver.payload, &mut idx).unwrap(),
            "ctag"
        );
        let delivery_tag = amqp_take_u64(&deliver.payload, &mut idx).unwrap();
        let header = amqp_read_frame(&mut reader).unwrap();
        assert_eq!(header.frame_type, AMQP_FRAME_HEADER);
        let body = amqp_read_frame(&mut reader).unwrap();
        assert_eq!(body.frame_type, AMQP_FRAME_BODY);
        assert_eq!(body.payload, b"async payload");

        let mut ack = Vec::new();
        amqp_push_u64(&mut ack, delivery_tag);
        ack.push(0);
        amqp_write_method(&mut s, 1, 60, 80, &ack).unwrap();
        std::thread::sleep(Duration::from_millis(25));

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(actions, vec!["publish", "deliver", "ack"]);
        assert_eq!(events[1].detail.get("payload").unwrap(), "async payload");
    }

    #[test]
    fn rabbit_amqp_exchange_bind_and_publisher_confirm_route_to_queue() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Rabbit, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://rabbit" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("amqp://127.0.0.1:")
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let mut reader = BufReader::new(s.try_clone().unwrap());
        amqp_test_open_channel(&mut s, &mut reader);

        let mut exchange = Vec::new();
        amqp_push_u16(&mut exchange, 0);
        amqp_push_shortstr(&mut exchange, "events");
        amqp_push_shortstr(&mut exchange, "direct");
        exchange.push(0);
        amqp_push_table_empty(&mut exchange);
        amqp_write_method(&mut s, 1, 40, 10, &exchange).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 40, 11);

        let mut declare = Vec::new();
        amqp_push_u16(&mut declare, 0);
        amqp_push_shortstr(&mut declare, "work");
        declare.push(0);
        amqp_push_table_empty(&mut declare);
        amqp_write_method(&mut s, 1, 50, 10, &declare).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 50, 11);

        let mut bind = Vec::new();
        amqp_push_u16(&mut bind, 0);
        amqp_push_shortstr(&mut bind, "work");
        amqp_push_shortstr(&mut bind, "events");
        amqp_push_shortstr(&mut bind, "orders.created");
        bind.push(0);
        amqp_push_table_empty(&mut bind);
        amqp_write_method(&mut s, 1, 50, 20, &bind).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 50, 21);

        amqp_write_method(&mut s, 1, 85, 10, &[0]).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 85, 11);

        let mut publish = Vec::new();
        amqp_push_u16(&mut publish, 0);
        amqp_push_shortstr(&mut publish, "events");
        amqp_push_shortstr(&mut publish, "orders.created");
        publish.push(0);
        amqp_write_method(&mut s, 1, 60, 40, &publish).unwrap();
        amqp_write_content(&mut s, 1, b"exchange payload").unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 60, 80);

        let mut get = Vec::new();
        amqp_push_u16(&mut get, 0);
        amqp_push_shortstr(&mut get, "work");
        get.push(0);
        amqp_write_method(&mut s, 1, 60, 70, &get).unwrap();
        let get_ok = amqp_read_frame(&mut reader).unwrap();
        assert_amqp_method_ref(&get_ok, 1, 60, 71);
        let mut idx = 4;
        let delivery_tag = amqp_take_u64(&get_ok.payload, &mut idx).unwrap();
        let header = amqp_read_frame(&mut reader).unwrap();
        assert_eq!(header.frame_type, AMQP_FRAME_HEADER);
        let body = amqp_read_frame(&mut reader).unwrap();
        assert_eq!(body.frame_type, AMQP_FRAME_BODY);
        assert_eq!(body.payload, b"exchange payload");

        let mut ack = Vec::new();
        amqp_push_u64(&mut ack, delivery_tag);
        ack.push(0);
        amqp_write_method(&mut s, 1, 60, 80, &ack).unwrap();
        std::thread::sleep(Duration::from_millis(25));

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(actions, vec!["publish", "deliver", "ack"]);
        assert_eq!(
            events[0].detail.get("destination").unwrap(),
            "orders.created"
        );
        assert_eq!(events[1].detail.get("destination").unwrap(), "work");
        assert_eq!(events[1].detail.get("payload").unwrap(), "exchange payload");
    }

    #[test]
    fn rabbit_amqp_basic_nack_requeues_delivery() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Rabbit, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://rabbit" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("amqp://127.0.0.1:")
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let mut reader = BufReader::new(s.try_clone().unwrap());
        amqp_test_open_channel(&mut s, &mut reader);

        let mut declare = Vec::new();
        amqp_push_u16(&mut declare, 0);
        amqp_push_shortstr(&mut declare, "work");
        declare.push(0);
        amqp_push_table_empty(&mut declare);
        amqp_write_method(&mut s, 1, 50, 10, &declare).unwrap();
        assert_amqp_method(amqp_read_frame(&mut reader).unwrap(), 1, 50, 11);

        let mut publish = Vec::new();
        amqp_push_u16(&mut publish, 0);
        amqp_push_shortstr(&mut publish, "");
        amqp_push_shortstr(&mut publish, "work");
        publish.push(0);
        amqp_write_method(&mut s, 1, 60, 40, &publish).unwrap();
        amqp_write_content(&mut s, 1, b"retry payload").unwrap();

        let mut get = Vec::new();
        amqp_push_u16(&mut get, 0);
        amqp_push_shortstr(&mut get, "work");
        get.push(0);
        amqp_write_method(&mut s, 1, 60, 70, &get).unwrap();
        let first_get_ok = amqp_read_frame(&mut reader).unwrap();
        assert_amqp_method_ref(&first_get_ok, 1, 60, 71);
        let mut idx = 4;
        let first_delivery_tag = amqp_take_u64(&first_get_ok.payload, &mut idx).unwrap();
        assert_eq!(
            amqp_read_frame(&mut reader).unwrap().frame_type,
            AMQP_FRAME_HEADER
        );
        assert_eq!(
            amqp_read_frame(&mut reader).unwrap().payload,
            b"retry payload"
        );

        let mut nack = Vec::new();
        amqp_push_u64(&mut nack, first_delivery_tag);
        nack.push(0b10);
        amqp_write_method(&mut s, 1, 60, 120, &nack).unwrap();

        let mut get_again = Vec::new();
        amqp_push_u16(&mut get_again, 0);
        amqp_push_shortstr(&mut get_again, "work");
        get_again.push(0);
        amqp_write_method(&mut s, 1, 60, 70, &get_again).unwrap();
        let second_get_ok = amqp_read_frame(&mut reader).unwrap();
        assert_amqp_method_ref(&second_get_ok, 1, 60, 71);
        let mut idx = 4;
        let second_delivery_tag = amqp_take_u64(&second_get_ok.payload, &mut idx).unwrap();
        assert_ne!(first_delivery_tag, second_delivery_tag);
        assert_eq!(
            amqp_read_frame(&mut reader).unwrap().frame_type,
            AMQP_FRAME_HEADER
        );
        assert_eq!(
            amqp_read_frame(&mut reader).unwrap().payload,
            b"retry payload"
        );

        let mut ack = Vec::new();
        amqp_push_u64(&mut ack, second_delivery_tag);
        ack.push(0);
        amqp_write_method(&mut s, 1, 60, 80, &ack).unwrap();
        std::thread::sleep(Duration::from_millis(25));

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(
            actions,
            vec!["publish", "deliver", "nack", "deliver", "ack"]
        );
        assert_eq!(
            events[2].detail.get("payload").unwrap(),
            &first_delivery_tag.to_string()
        );
        assert_eq!(events[3].detail.get("payload").unwrap(), "retry payload");
        assert_eq!(
            events[4].detail.get("payload").unwrap(),
            &second_delivery_tag.to_string()
        );
    }

    #[test]
    fn nats_protocol_server_records_publish_deliver() {
        let dir = TempDir::new().unwrap();
        let stub = BrokerStub::start(StubKind::Nats, dir.path()).unwrap();
        let endpoint = stub.endpoint();
        if endpoint == "loopback://nats" {
            return;
        }
        let port: u16 = endpoint
            .trim_start_matches("nats://127.0.0.1:")
            .parse()
            .unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let mut reader = BufReader::new(s.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.starts_with("INFO "), "{line}");

        s.write_all(b"CONNECT {\"verbose\":false}\r\nPING\r\n")
            .unwrap();
        let handshake = read_until(&mut reader, "PONG\r\n");
        assert!(handshake.contains("PONG"), "{handshake}");

        s.write_all(b"SUB events 1\r\nPING\r\n").unwrap();
        let flush = read_until(&mut reader, "PONG\r\n");
        assert!(flush.contains("PONG"), "{flush}");

        s.write_all(b"PUB events 11\r\nhello world\r\n").unwrap();
        let delivery = read_until(&mut reader, "hello world\r\n");
        assert!(
            delivery.contains("MSG events 1 11\r\nhello world\r\n"),
            "{delivery:?}"
        );

        let events = stub.drain_events();
        let actions: Vec<&str> = events
            .iter()
            .map(|ev| ev.detail.get("action").unwrap().as_str())
            .collect();
        assert_eq!(actions, vec!["publish", "deliver"]);
        assert_eq!(events[0].detail.get("destination").unwrap(), "events");
        assert_eq!(events[1].detail.get("payload").unwrap(), "hello world");
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

    fn kafka_test_request(api_key: i16, version: i16, correlation_id: i32, body: &[u8]) -> Vec<u8> {
        let mut request = Vec::new();
        kafka_push_i16(&mut request, api_key);
        kafka_push_i16(&mut request, version);
        kafka_push_i32(&mut request, correlation_id);
        kafka_push_nullable_string(&mut request, Some("nyx-test"));
        if kafka_api_uses_flexible_header(api_key, version) {
            kafka_push_unsigned_varint(&mut request, 0);
        }
        request.extend_from_slice(body);
        let mut framed = Vec::new();
        kafka_push_i32(&mut framed, request.len() as i32);
        framed.extend_from_slice(&request);
        framed
    }

    fn kafka_roundtrip(port: u16, request: Vec<u8>) -> Vec<u8> {
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        s.write_all(&request).unwrap();
        let mut len_buf = [0_u8; 4];
        s.read_exact(&mut len_buf).unwrap();
        let len = i32::from_be_bytes(len_buf) as usize;
        let mut response = vec![0_u8; len];
        s.read_exact(&mut response).unwrap();
        response
    }

    fn kafka_test_fetch_values(response: &[u8]) -> Vec<String> {
        let mut reader = KafkaReader::new(response);
        let _correlation_id = reader.i32().unwrap();
        let _throttle_ms = reader.i32().unwrap();
        let topic_len = reader.array_len().unwrap();
        let mut values = Vec::new();
        for _ in 0..topic_len {
            let _topic = reader.string().unwrap();
            let partition_len = reader.array_len().unwrap();
            for _ in 0..partition_len {
                let _partition = reader.i32().unwrap();
                assert_eq!(reader.i16().unwrap(), 0);
                let _high_watermark = reader.i64().unwrap();
                let message_set = reader.bytes().unwrap();
                values.extend(kafka_message_set_values(message_set));
            }
        }
        values
    }

    fn pubsub_grpc_unary<M, R>(port: u16, path: &str, message: &M) -> R
    where
        M: prost::Message,
        R: prost::Message + Default,
    {
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();
        let framed = pubsub_grpc_frame(&payload);
        let response = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async move {
                let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
                    .await
                    .unwrap();
                let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                let request = http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap();
                let (response, mut send_stream) = client.send_request(request, false).unwrap();
                send_stream
                    .send_data(bytes::Bytes::from(framed), true)
                    .unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), 200);
                let framed_response = pubsub_grpc_read_all(response.into_body()).await;
                pubsub_grpc_unframe(&framed_response).unwrap_or_default()
            });
        R::decode(response.as_slice()).unwrap()
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

    fn read_until(reader: &mut BufReader<TcpStream>, needle: &str) -> String {
        let mut out = String::new();
        while !out.contains(needle) {
            let mut line = String::new();
            let n = reader.read_line(&mut line).unwrap();
            if n == 0 {
                break;
            }
            out.push_str(&line);
            if line.starts_with("MSG ") {
                let size = line
                    .split_whitespace()
                    .last()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap();
                let mut payload = vec![0_u8; size + 2];
                reader.read_exact(&mut payload).unwrap();
                out.push_str(&String::from_utf8_lossy(&payload));
            }
        }
        out
    }

    fn assert_amqp_method(frame: AmqpFrame, channel: u16, class_id: u16, method_id: u16) {
        assert_amqp_method_ref(&frame, channel, class_id, method_id);
    }

    fn assert_amqp_method_ref(frame: &AmqpFrame, channel: u16, class_id: u16, method_id: u16) {
        assert_eq!(frame.frame_type, AMQP_FRAME_METHOD);
        assert_eq!(frame.channel, channel);
        assert_eq!(amqp_method_id(&frame.payload), Some((class_id, method_id)));
    }

    fn amqp_test_open_channel(s: &mut TcpStream, reader: &mut BufReader<TcpStream>) {
        s.write_all(b"AMQP\0\0\x09\x01").unwrap();
        assert_amqp_method(amqp_read_frame(reader).unwrap(), 0, 10, 10);

        let mut start_ok = Vec::new();
        amqp_push_table_empty(&mut start_ok);
        amqp_push_shortstr(&mut start_ok, "PLAIN");
        amqp_push_longstr(&mut start_ok, "\0guest\0guest");
        amqp_push_shortstr(&mut start_ok, "en_US");
        amqp_write_method(s, 0, 10, 11, &start_ok).unwrap();
        assert_amqp_method(amqp_read_frame(reader).unwrap(), 0, 10, 30);

        let mut tune_ok = Vec::new();
        amqp_push_u16(&mut tune_ok, 2047);
        amqp_push_u32(&mut tune_ok, 131_072);
        amqp_push_u16(&mut tune_ok, 0);
        amqp_write_method(s, 0, 10, 31, &tune_ok).unwrap();

        let mut open = Vec::new();
        amqp_push_shortstr(&mut open, "/");
        amqp_push_shortstr(&mut open, "");
        open.push(0);
        amqp_write_method(s, 0, 10, 40, &open).unwrap();
        assert_amqp_method(amqp_read_frame(reader).unwrap(), 0, 10, 41);

        let mut channel_open = Vec::new();
        amqp_push_longstr(&mut channel_open, "");
        amqp_write_method(s, 1, 20, 10, &channel_open).unwrap();
        assert_amqp_method(amqp_read_frame(reader).unwrap(), 1, 20, 11);
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
