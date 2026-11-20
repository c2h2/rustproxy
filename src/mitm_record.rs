//! HTTP flow recorder behind the `--mitm` traffic browser.
//!
//! Decrypted (or plain) HTTP/1.x byte streams are parsed passively — the
//! relay never waits on, or is altered by, the parser — into request/response
//! "flows" kept in a bounded in-memory store. The web interface lists them,
//! shows headers and bodies, and exports HAR files or a zip of the fetched
//! site content.

use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use bytes::Bytes;
use futures_util::Stream;
use serde_json::{json, Value};

/// Bytes of one body kept in memory; the rest is counted but not stored.
pub const MAX_BODY_STORE: usize = 16 * 1024 * 1024;
/// Flows kept regardless of how small they are.
const MAX_FLOWS: usize = 20_000;
/// A message head larger than this is not treated as HTTP.
const MAX_HEAD: usize = 256 * 1024;
/// Ceiling on a decompressed body (decompression-bomb guard).
const MAX_DECODED: u64 = 64 * 1024 * 1024;

pub type FlowRef = Arc<Mutex<Flow>>;

/// One request/response exchange.
#[derive(Debug, Clone, Default)]
pub struct Flow {
    pub id: u64,
    /// Change counter value at the last update (drives incremental polling).
    pub rev: u64,
    pub started_ms: u64,
    pub duration_ms: Option<u64>,
    pub client: String,
    pub server: String,
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub req_version: String,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Vec<u8>,
    pub req_size: u64,
    pub status: Option<u16>,
    pub reason: String,
    pub resp_version: String,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body: Vec<u8>,
    pub resp_size: u64,
    /// `pending`, `done`, `aborted` or `upgraded` (e.g. WebSocket).
    pub state: &'static str,
    evicted: bool,
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

impl Flow {
    pub fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.host, self.path)
    }

    fn content_type(&self) -> &str {
        header(&self.resp_headers, "content-type").unwrap_or("")
    }

    /// Case-insensitive substring match over method, URL and status — the
    /// same string the browser UI filters on.
    pub fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        let hay = format!(
            "{} {} {}",
            self.method,
            self.url(),
            self.status.map(|s| s.to_string()).unwrap_or_default()
        )
        .to_ascii_lowercase();
        hay.contains(&needle.to_ascii_lowercase())
    }

    pub fn summary(&self) -> Value {
        json!({
            "id": self.id,
            "rev": self.rev,
            "t": self.started_ms,
            "ms": self.duration_ms,
            "client": self.client,
            "server": self.server,
            "scheme": self.scheme,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "type": self.content_type().split(';').next().unwrap_or("").trim(),
            "req_size": self.req_size,
            "resp_size": self.resp_size,
            "state": self.state,
        })
    }

    pub fn detail(&self) -> Value {
        let pairs = |h: &[(String, String)]| -> Vec<Value> { h.iter().map(|(k, v)| json!([k, v])).collect() };
        let mut v = self.summary();
        let extra = json!({
            "url": self.url(),
            "req_version": self.req_version,
            "req_headers": pairs(&self.req_headers),
            "req_stored": self.req_body.len(),
            "reason": self.reason,
            "resp_version": self.resp_version,
            "resp_headers": pairs(&self.resp_headers),
            "resp_stored": self.resp_body.len(),
            "resp_encoding": header(&self.resp_headers, "content-encoding").unwrap_or(""),
            "req_encoding": header(&self.req_headers, "content-encoding").unwrap_or(""),
        });
        if let (Some(a), Some(b)) = (v.as_object_mut(), extra.as_object()) {
            a.extend(b.clone());
        }
        v
    }

    /// Body with any `Content-Encoding` removed. `response == false` gives
    /// the request body.
    pub fn decoded_body(&self, response: bool) -> Vec<u8> {
        let (headers, body) = if response {
            (&self.resp_headers, &self.resp_body)
        } else {
            (&self.req_headers, &self.req_body)
        };
        decode_body(header(headers, "content-encoding").unwrap_or(""), body)
    }
}

/// Undo `Content-Encoding`. On an unknown coding or a damaged / truncated
/// stream, whatever could be decoded (or the raw bytes) is returned.
pub fn decode_body(encoding: &str, body: &[u8]) -> Vec<u8> {
    let mut data = body.to_vec();
    // Codings are listed in the order applied, so undo them back to front.
    for coding in encoding.rsplit(',').map(|c| c.trim().to_ascii_lowercase()) {
        let mut out = Vec::new();
        let ok = match coding.as_str() {
            "" | "identity" => continue,
            "gzip" | "x-gzip" => {
                let _ = flate2::read::MultiGzDecoder::new(&data[..]).take(MAX_DECODED).read_to_end(&mut out);
                !out.is_empty()
            }
            "deflate" => {
                let _ = flate2::read::ZlibDecoder::new(&data[..]).take(MAX_DECODED).read_to_end(&mut out);
                if out.is_empty() {
                    // Some servers send raw deflate without the zlib wrapper.
                    let _ = flate2::read::DeflateDecoder::new(&data[..]).take(MAX_DECODED).read_to_end(&mut out);
                }
                !out.is_empty()
            }
            "br" => {
                let _ = brotli_decompressor::Decompressor::new(&data[..], 16 * 1024)
                    .take(MAX_DECODED)
                    .read_to_end(&mut out);
                !out.is_empty()
            }
            _ => false,
        };
        if !ok {
            return data;
        }
        data = out;
    }
    data
}

struct Store {
    flows: VecDeque<FlowRef>,
}

pub struct Recorder {
    store: Mutex<Store>,
    recording: AtomicBool,
    next_id: AtomicU64,
    rev: AtomicU64,
    /// Bumped by `clear` so browsers drop what they have listed.
    epoch: AtomicU64,
    stored_bytes: AtomicUsize,
    max_bytes: usize,
}

/// Where a connection's flows come from and go to.
#[derive(Debug, Clone)]
pub struct ConnMeta {
    pub client: String,
    pub server: String,
    pub scheme: &'static str,
    /// Used when a request carries no `Host` header.
    pub default_host: String,
}

impl Recorder {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            store: Mutex::new(Store { flows: VecDeque::new() }),
            recording: AtomicBool::new(true),
            next_id: AtomicU64::new(1),
            rev: AtomicU64::new(0),
            epoch: AtomicU64::new(1),
            stored_bytes: AtomicUsize::new(0),
            max_bytes: max_bytes.max(1024 * 1024),
        }
    }

    pub fn recording(&self) -> bool {
        self.recording.load(Ordering::Relaxed)
    }

    pub fn set_recording(&self, on: bool) {
        self.recording.store(on, Ordering::Relaxed);
    }

    fn touch(&self, flow: &mut Flow) {
        flow.rev = self.rev.fetch_add(1, Ordering::Relaxed) + 1;
    }

    /// Start a flow from a parsed request head. `None` while paused.
    pub fn begin(
        &self,
        meta: &ConnMeta,
        method: &str,
        target: &str,
        version: &str,
        headers: Vec<(String, String)>,
    ) -> Option<FlowRef> {
        if !self.recording() {
            return None;
        }
        // Proxies receive absolute-form targets; split them back apart.
        let (mut scheme, mut host, mut path) = (meta.scheme.to_string(), String::new(), target.to_string());
        for (prefix, s) in [("http://", "http"), ("https://", "https")] {
            if target.len() > prefix.len() && target[..prefix.len()].eq_ignore_ascii_case(prefix) {
                let rest = &target[prefix.len()..];
                let cut = rest.find(['/', '?']).unwrap_or(rest.len());
                scheme = s.to_string();
                host = rest[..cut].to_string();
                path = if cut == rest.len() { "/".to_string() } else { rest[cut..].to_string() };
                if !path.starts_with('/') {
                    path.insert(0, '/');
                }
            }
        }
        if host.is_empty() {
            host = header(&headers, "host").unwrap_or(&meta.default_host).to_string();
        }

        let mut flow = Flow {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            started_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            client: meta.client.clone(),
            server: meta.server.clone(),
            scheme,
            host,
            method: method.to_string(),
            path,
            req_version: version.to_string(),
            req_headers: headers,
            state: "pending",
            ..Flow::default()
        };
        self.touch(&mut flow);
        let flow = Arc::new(Mutex::new(flow));

        let mut store = self.store.lock().unwrap();
        store.flows.push_back(flow.clone());
        while store.flows.len() > MAX_FLOWS {
            self.evict_front(&mut store);
        }
        Some(flow)
    }

    fn evict_front(&self, store: &mut Store) {
        if let Some(old) = store.flows.pop_front() {
            let mut f = old.lock().unwrap();
            f.evicted = true;
            self.stored_bytes.fetch_sub(f.req_body.len() + f.resp_body.len(), Ordering::Relaxed);
            f.req_body = Vec::new();
            f.resp_body = Vec::new();
        }
    }

    /// Append body bytes; storage is capped per body and overall (oldest
    /// flows are dropped first), sizes always reflect the real total.
    pub fn append(&self, flow: &FlowRef, response: bool, data: &[u8]) {
        {
            let mut f = flow.lock().unwrap();
            let evicted = f.evicted;
            let (body, size) = if response {
                let f = &mut *f;
                (&mut f.resp_body, &mut f.resp_size)
            } else {
                let f = &mut *f;
                (&mut f.req_body, &mut f.req_size)
            };
            *size += data.len() as u64;
            let room = MAX_BODY_STORE.saturating_sub(body.len()).min(data.len());
            if evicted || room == 0 {
                return;
            }
            body.extend_from_slice(&data[..room]);
            self.stored_bytes.fetch_add(room, Ordering::Relaxed);
        }
        if self.stored_bytes.load(Ordering::Relaxed) > self.max_bytes {
            let mut store = self.store.lock().unwrap();
            while self.stored_bytes.load(Ordering::Relaxed) > self.max_bytes && store.flows.len() > 1 {
                self.evict_front(&mut store);
            }
        }
    }

    pub fn set_response(&self, flow: &FlowRef, status: u16, reason: &str, version: &str, headers: Vec<(String, String)>) {
        let mut f = flow.lock().unwrap();
        f.status = Some(status);
        f.reason = reason.to_string();
        f.resp_version = version.to_string();
        f.resp_headers = headers;
        self.touch(&mut f);
    }

    /// Close a flow. A flow already closed keeps its first outcome.
    pub fn finish(&self, flow: &FlowRef, state: &'static str) {
        let mut f = flow.lock().unwrap();
        if f.state != "pending" {
            return;
        }
        f.state = state;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        f.duration_ms = Some(now.saturating_sub(f.started_ms));
        self.touch(&mut f);
    }

    pub fn clear(&self) {
        let mut store = self.store.lock().unwrap();
        while !store.flows.is_empty() {
            self.evict_front(&mut store);
        }
        self.epoch.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self, id: u64) -> Option<Flow> {
        let store = self.store.lock().unwrap();
        store
            .flows
            .iter()
            .map(|f| f.lock().unwrap())
            .find(|f| f.id == id)
            .map(|f| f.clone())
    }

    /// Snapshot of every flow matching `filter` (see [`Flow::matches`]).
    pub fn snapshot(&self, filter: &str) -> Vec<Flow> {
        let store = self.store.lock().unwrap();
        store
            .flows
            .iter()
            .map(|f| f.lock().unwrap())
            .filter(|f| f.matches(filter))
            .map(|f| f.clone())
            .collect()
    }

    /// Summaries of flows changed after revision `since`, plus the state a
    /// polling client needs to stay in sync.
    pub fn poll(&self, since: u64) -> Value {
        let store = self.store.lock().unwrap();
        let mut rev = since;
        let mut changed = Vec::new();
        let mut first_id = 0;
        for (i, f) in store.flows.iter().enumerate() {
            let f = f.lock().unwrap();
            if i == 0 {
                first_id = f.id;
            }
            if f.rev > since {
                rev = rev.max(f.rev);
                changed.push(f.summary());
            }
        }
        json!({
            "epoch": self.epoch.load(Ordering::Relaxed),
            "rev": rev,
            "recording": self.recording(),
            "first_id": first_id,
            "count": store.flows.len(),
            "stored_bytes": self.stored_bytes.load(Ordering::Relaxed),
            "max_bytes": self.max_bytes,
            "flows": changed,
        })
    }
}

/* ------------------------- HTTP/1.x parsing ------------------------- */

#[derive(Debug, Clone, Copy, PartialEq)]
enum Framing {
    /// Waiting for a complete message head.
    Head,
    Length(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailers,
    UntilClose,
}

struct Head {
    /// Method (request) or reason phrase (response).
    word: String,
    /// Request target; empty for responses.
    target: String,
    status: u16,
    version: String,
    headers: Vec<(String, String)>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse a complete head (`bytes` ends with the blank line).
fn parse_head(bytes: &[u8], request: bool) -> Option<Head> {
    let mut storage = [httparse::EMPTY_HEADER; 128];
    let collect = |hs: &[httparse::Header<'_>]| -> Vec<(String, String)> {
        hs.iter()
            .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
            .collect()
    };
    if request {
        let mut req = httparse::Request::new(&mut storage);
        match req.parse(bytes) {
            Ok(httparse::Status::Complete(_)) => Some(Head {
                word: req.method?.to_string(),
                target: req.path?.to_string(),
                status: 0,
                version: format!("HTTP/1.{}", req.version?),
                headers: collect(req.headers),
            }),
            _ => None,
        }
    } else {
        let mut resp = httparse::Response::new(&mut storage);
        match resp.parse(bytes) {
            Ok(httparse::Status::Complete(_)) => Some(Head {
                word: resp.reason.unwrap_or("").to_string(),
                target: String::new(),
                status: resp.code?,
                version: format!("HTTP/1.{}", resp.version?),
                headers: collect(resp.headers),
            }),
            _ => None,
        }
    }
}

fn body_framing(headers: &[(String, String)]) -> Option<Framing> {
    let chunked = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        .any(|(_, v)| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return Some(Framing::ChunkSize);
    }
    header(headers, "content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Framing::Length)
}

/// What the framing layer found in one direction's byte stream.
enum Event<'a> {
    Head(Head),
    Body(&'a [u8]),
    End,
}

/// One direction of an HTTP/1.x connection.
struct Direction {
    buf: Vec<u8>,
    framing: Framing,
}

/// Passive parser for one HTTP/1.x connection, fed from both directions.
pub struct H1Session {
    rec: Arc<Recorder>,
    meta: ConnMeta,
    req: Direction,
    resp: Direction,
    /// Requests awaiting their response, oldest first. `None` = not recorded
    /// (paused), kept so responses still pair up with the right request.
    pending: VecDeque<(Option<FlowRef>, bool)>,
    /// Flow whose request body is currently streaming.
    req_flow: Option<FlowRef>,
    /// Set once the stream stops being parseable HTTP/1.x (or is upgraded).
    opaque: bool,
}

impl H1Session {
    pub fn new(rec: Arc<Recorder>, meta: ConnMeta) -> Self {
        let dir = || Direction { buf: Vec::new(), framing: Framing::Head };
        Self { rec, meta, req: dir(), resp: dir(), pending: VecDeque::new(), req_flow: None, opaque: false }
    }

    /// Bytes sent by the client.
    pub fn client_data(&mut self, data: &[u8]) {
        self.feed(true, data);
    }

    /// Bytes sent by the server.
    pub fn server_data(&mut self, data: &[u8]) {
        self.feed(false, data);
    }

    fn feed(&mut self, request: bool, data: &[u8]) {
        if self.opaque {
            return;
        }
        let mut dir = std::mem::replace(
            if request { &mut self.req } else { &mut self.resp },
            Direction { buf: Vec::new(), framing: Framing::Head },
        );
        dir.buf.extend_from_slice(data);
        let mut pos = 0;
        while !self.opaque {
            let rest = &dir.buf[pos..];
            match dir.framing {
                Framing::Head => {
                    let Some(end) = find(rest, b"\r\n\r\n") else {
                        if rest.len() > MAX_HEAD {
                            self.opaque = true;
                        }
                        break;
                    };
                    let Some(head) = parse_head(&rest[..end + 4], request) else {
                        self.opaque = true;
                        break;
                    };
                    pos += end + 4;
                    dir.framing = self.on_event(request, Event::Head(head));
                    if dir.framing == Framing::Head {
                        // No body: the message is already complete.
                        self.on_event(request, Event::End);
                    }
                }
                Framing::Length(0) => {
                    self.on_event(request, Event::End);
                    dir.framing = Framing::Head;
                }
                Framing::Length(n) | Framing::ChunkData(n) => {
                    if rest.is_empty() {
                        break;
                    }
                    let take = (n.min(rest.len() as u64)) as usize;
                    self.on_event(request, Event::Body(&rest[..take]));
                    pos += take;
                    let left = n - take as u64;
                    dir.framing = match dir.framing {
                        Framing::Length(_) => Framing::Length(left),
                        _ if left == 0 => Framing::ChunkEnd,
                        _ => Framing::ChunkData(left),
                    };
                }
                Framing::ChunkSize => {
                    let Some(end) = find(rest, b"\r\n") else { break };
                    let line = String::from_utf8_lossy(&rest[..end]);
                    let hex = line.split(';').next().unwrap_or("").trim();
                    let Ok(size) = u64::from_str_radix(hex, 16) else {
                        self.opaque = true;
                        break;
                    };
                    pos += end + 2;
                    dir.framing = if size == 0 { Framing::Trailers } else { Framing::ChunkData(size) };
                }
                Framing::ChunkEnd => {
                    if rest.len() < 2 {
                        break;
                    }
                    pos += 2;
                    dir.framing = Framing::ChunkSize;
                }
                Framing::Trailers => {
                    let Some(end) = find(rest, b"\r\n") else { break };
                    pos += end + 2;
                    if end == 0 {
                        self.on_event(request, Event::End);
                        dir.framing = Framing::Head;
                    }
                }
                Framing::UntilClose => {
                    if !rest.is_empty() {
                        self.on_event(request, Event::Body(rest));
                        pos = dir.buf.len();
                    }
                    break;
                }
            }
        }
        dir.buf.drain(..pos);
        if self.opaque {
            dir.buf = Vec::new();
        }
        *(if request { &mut self.req } else { &mut self.resp }) = dir;
    }

    /// Apply a framing event; for `Head` returns the framing of the body
    /// that follows (`Framing::Head` when there is none).
    fn on_event(&mut self, request: bool, event: Event<'_>) -> Framing {
        match (request, event) {
            (true, Event::Head(head)) => {
                let framing = body_framing(&head.headers).unwrap_or(Framing::Head);
                let is_head = head.word.eq_ignore_ascii_case("HEAD");
                let flow = self.rec.begin(&self.meta, &head.word, &head.target, &head.version, head.headers);
                self.req_flow = flow.clone();
                self.pending.push_back((flow, is_head));
                framing
            }
            (true, Event::Body(data)) => {
                if let Some(ref flow) = self.req_flow {
                    self.rec.append(flow, false, data);
                }
                Framing::Head
            }
            (true, Event::End) => {
                self.req_flow = None;
                Framing::Head
            }
            (false, Event::Head(head)) => {
                let Some((flow, is_head)) = self.pending.front().cloned() else {
                    // A response nobody asked for: not HTTP as we know it.
                    self.opaque = true;
                    return Framing::Head;
                };
                if head.status == 101 {
                    if let Some(ref flow) = flow {
                        self.rec.set_response(flow, head.status, &head.word, &head.version, head.headers);
                        self.rec.finish(flow, "upgraded");
                    }
                    self.pending.pop_front();
                    self.opaque = true;
                    return Framing::Head;
                }
                if (100..200).contains(&head.status) {
                    // Interim response (100 Continue, 103 Early Hints): the
                    // real one follows. Park the framing in a state that
                    // completes without popping the pending request.
                    self.pending.push_front((None, false));
                    return Framing::Head;
                }
                let framing = if is_head || head.status == 204 || head.status == 304 {
                    Framing::Head
                } else {
                    body_framing(&head.headers).unwrap_or(Framing::UntilClose)
                };
                if let Some(ref flow) = flow {
                    self.rec.set_response(flow, head.status, &head.word, &head.version, head.headers);
                }
                framing
            }
            (false, Event::Body(data)) => {
                if let Some((Some(flow), _)) = self.pending.front() {
                    self.rec.append(flow, true, data);
                }
                Framing::Head
            }
            (false, Event::End) => {
                if let Some((Some(flow), _)) = self.pending.pop_front() {
                    self.rec.finish(&flow, "done");
                }
                Framing::Head
            }
        }
    }
}

impl Drop for H1Session {
    fn drop(&mut self) {
        // A response delimited by connection close ends here, successfully.
        let until_close = self.resp.framing == Framing::UntilClose;
        for (i, (flow, _)) in self.pending.drain(..).enumerate() {
            if let Some(flow) = flow {
                self.rec.finish(&flow, if i == 0 && until_close { "done" } else { "aborted" });
            }
        }
    }
}

/* -------------------- hyper body recording (http mode) -------------------- */

/// Streams a hyper body through unchanged while copying it into a flow.
/// Used for plain-HTTP requests the forward proxy handles itself.
pub struct RecordedBody {
    inner: hyper::Body,
    rec: Arc<Recorder>,
    flow: FlowRef,
    response: bool,
    ended: bool,
}

impl RecordedBody {
    pub fn wrap(inner: hyper::Body, rec: Arc<Recorder>, flow: FlowRef, response: bool) -> hyper::Body {
        hyper::Body::wrap_stream(Self { inner, rec, flow, response, ended: false })
    }
}

impl Stream for RecordedBody {
    type Item = Result<Bytes, hyper::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let item = Pin::new(&mut self.inner).poll_next(cx);
        match &item {
            Poll::Ready(Some(Ok(chunk))) => {
                self.rec.append(&self.flow, self.response, chunk);
                // A length-delimited body is complete with its last chunk;
                // hyper may never poll again to observe the end.
                if hyper::body::HttpBody::is_end_stream(&self.inner) {
                    self.ended = true;
                }
            }
            Poll::Ready(None) => self.ended = true,
            _ => {}
        }
        item
    }
}

impl Drop for RecordedBody {
    fn drop(&mut self) {
        if self.response {
            self.rec.finish(&self.flow, if self.ended { "done" } else { "aborted" });
        }
    }
}

pub fn hyper_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect()
}

/// Peer address as recorded for flows (IPv4-mapped addresses unwrapped).
pub fn addr_string(addr: SocketAddr) -> String {
    SocketAddr::new(addr.ip().to_canonical(), addr.port()).to_string()
}

/* ------------------------------ Exports ------------------------------ */

fn iso_time(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

/// HAR 1.2 document for the given flows (bodies decoded; binary as base64).
pub fn export_har(flows: &[Flow]) -> Value {
    let headers = |h: &[(String, String)]| -> Vec<Value> {
        h.iter().map(|(k, v)| json!({"name": k, "value": v})).collect()
    };
    let content = |body: Vec<u8>, mime: &str| -> Value {
        match String::from_utf8(body) {
            Ok(text) => json!({"size": text.len(), "mimeType": mime, "text": text}),
            Err(e) => {
                let bytes = e.into_bytes();
                json!({
                    "size": bytes.len(),
                    "mimeType": mime,
                    "text": base64::engine::general_purpose::STANDARD.encode(&bytes),
                    "encoding": "base64",
                })
            }
        }
    };

    let entries: Vec<Value> = flows
        .iter()
        .map(|f| {
            let query: Vec<Value> = f
                .path
                .split_once('?')
                .map(|(_, q)| q)
                .unwrap_or("")
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| {
                    let (k, v) = p.split_once('=').unwrap_or((p, ""));
                    json!({"name": k, "value": v})
                })
                .collect();
            let mut request = json!({
                "method": f.method,
                "url": f.url(),
                "httpVersion": f.req_version,
                "headers": headers(&f.req_headers),
                "queryString": query,
                "cookies": [],
                "headersSize": -1,
                "bodySize": f.req_size,
            });
            if !f.req_body.is_empty() {
                let mime = header(&f.req_headers, "content-type").unwrap_or("");
                let c = content(f.decoded_body(false), mime);
                let mut post = json!({"mimeType": mime, "text": c["text"]});
                if !c["encoding"].is_null() {
                    post["encoding"] = c["encoding"].clone();
                }
                request["postData"] = post;
            }
            let time = f.duration_ms.unwrap_or(0);
            json!({
                "startedDateTime": iso_time(f.started_ms),
                "time": time,
                "request": request,
                "response": {
                    "status": f.status.unwrap_or(0),
                    "statusText": f.reason,
                    "httpVersion": f.resp_version,
                    "headers": headers(&f.resp_headers),
                    "cookies": [],
                    "content": content(f.decoded_body(true), f.content_type()),
                    "redirectURL": header(&f.resp_headers, "location").unwrap_or(""),
                    "headersSize": -1,
                    "bodySize": f.resp_size,
                },
                "cache": {},
                "timings": {"send": 0, "wait": time, "receive": 0},
                "serverIPAddress": f.server.rsplit_once(':').map(|(ip, _)| ip.trim_matches(['[', ']'])).unwrap_or(""),
                "_clientAddress": f.client,
                "_state": f.state,
            })
        })
        .collect();

    json!({
        "log": {
            "version": "1.2",
            "creator": {"name": "rustproxy", "version": env!("CARGO_PKG_VERSION")},
            "entries": entries,
        }
    })
}

fn extension_for(content_type: &str) -> &'static str {
    match content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "text/html" | "application/xhtml+xml" => "html",
        "text/css" => "css",
        "text/javascript" | "application/javascript" | "application/x-javascript" => "js",
        "application/json" => "json",
        "text/plain" => "txt",
        "text/xml" | "application/xml" => "xml",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        "font/woff2" => "woff2",
        "font/woff" => "woff",
        "application/pdf" => "pdf",
        "application/wasm" => "wasm",
        _ => "bin",
    }
}

/// Make one URL path segment safe as a file name on any platform.
fn safe_segment(seg: &str) -> String {
    let mut out: String = seg
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "-_.~%@+=,".contains(c) { c } else { '_' })
        .take(120)
        .collect();
    if out.is_empty() || out.chars().all(|c| c == '.') {
        out = "_".to_string();
    }
    out
}

/// File name inside the site dump for a flow: `host/path`, with `index.*`
/// for directory URLs, the query folded into the name and an extension
/// from the content type when the URL has none.
pub fn dump_path(flow: &Flow) -> String {
    let (path, query) = flow.path.split_once('?').unwrap_or((flow.path.as_str(), ""));
    let mut parts: Vec<String> = vec![safe_segment(&flow.host)];
    parts.extend(path.split('/').filter(|s| !s.is_empty() && *s != "." && *s != "..").map(safe_segment));
    let ext = extension_for(flow.content_type());
    if path.ends_with('/') || parts.len() == 1 {
        parts.push(format!("index.{}", if ext == "bin" { "html" } else { ext }));
    }
    let last = parts.last_mut().unwrap();
    if !query.is_empty() {
        last.push('_');
        last.push_str(&safe_segment(&query.chars().take(60).collect::<String>()));
    }
    if (!last.contains('.') || !query.is_empty()) && ext != "bin" && !last.ends_with(&format!(".{ext}")) {
        last.push('.');
        last.push_str(ext);
    }
    parts.join("/")
}

/// What a site dump contains, reported to the browser alongside the zip.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DumpStats {
    /// Flows written to `_records/` (every flow, whatever its status).
    pub records: usize,
    /// Of those, how many have a response (status line + headers).
    pub responses: usize,
    pub req_header_bytes: u64,
    pub req_body_bytes: u64,
    pub resp_header_bytes: u64,
    pub resp_body_bytes: u64,
    /// Site files under `host/path` (successful response bodies).
    pub site_files: usize,
    /// Flows left out because the zip hit its entry limit.
    pub skipped: usize,
}

fn head_text(start_line: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = format!("{start_line}\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Zip of the recorded traffic:
/// - `host/path` — every successfully fetched response body, a browsable
///   dump of the visited sites (most recent copy wins on repeats);
/// - `_records/<id>.http` — every flow in full: request line, headers and
///   body, then status line, headers and body (bodies as stored, with any
///   `Content-Encoding` removed);
/// - `_records/index.csv` and `_summary.txt` — counts and sizes per flow.
pub fn export_site_zip(flows: &[Flow]) -> (Vec<u8>, DumpStats) {
    // Classic zip counts entries in 16 bits; leave room for the index files.
    const MAX_ENTRIES: usize = 65_000;
    let mut stats = DumpStats::default();
    let mut site: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for f in flows {
        let ok = matches!(f.status, Some(200..=299)) && f.state == "done" && !f.resp_body.is_empty();
        if ok && !f.method.eq_ignore_ascii_case("HEAD") {
            site.insert(dump_path(f), f.decoded_body(true));
        }
    }

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut csv = String::from(
        "id,time,method,url,status,state,ms,client,server,req_header_bytes,req_body_bytes,req_body_stored,resp_header_bytes,resp_body_bytes,resp_body_stored\n",
    );
    for f in flows {
        if site.len() + files.len() >= MAX_ENTRIES {
            stats.skipped += 1;
            continue;
        }
        let req_head = head_text(&format!("{} {} {}", f.method, f.path, f.req_version), &f.req_headers);
        let req_body = f.decoded_body(false);
        let mut rec = format!(
            "# rustproxy record {} · {} · {} -> {} · {}{}\r\n",
            f.id,
            iso_time(f.started_ms),
            f.client,
            f.server,
            f.state,
            f.duration_ms.map(|ms| format!(" · {ms} ms")).unwrap_or_default()
        )
        .into_bytes();
        rec.extend_from_slice(&req_head);
        rec.extend_from_slice(&req_body);
        stats.req_header_bytes += req_head.len() as u64;
        stats.req_body_bytes += f.req_size;

        let mut resp_head_len = 0;
        if let Some(status) = f.status {
            let resp_head = head_text(&format!("{} {} {}", f.resp_version, status, f.reason), &f.resp_headers);
            resp_head_len = resp_head.len();
            rec.extend_from_slice(b"\r\n\r\n");
            rec.extend_from_slice(&resp_head);
            rec.extend_from_slice(&f.decoded_body(true));
            stats.responses += 1;
            stats.resp_header_bytes += resp_head_len as u64;
            stats.resp_body_bytes += f.resp_size;
        }
        if f.req_size > f.req_body.len() as u64 || f.resp_size > f.resp_body.len() as u64 {
            rec.extend_from_slice(b"\r\n# body truncated: only the first part was kept in memory\r\n");
        }
        files.insert(format!("_records/{:06}.http", f.id), rec);
        stats.records += 1;

        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            f.id,
            iso_time(f.started_ms),
            csv_field(&f.method),
            csv_field(&f.url()),
            f.status.map(|s| s.to_string()).unwrap_or_default(),
            f.state,
            f.duration_ms.map(|s| s.to_string()).unwrap_or_default(),
            csv_field(&f.client),
            csv_field(&f.server),
            req_head.len(),
            f.req_size,
            f.req_body.len(),
            resp_head_len,
            f.resp_size,
            f.resp_body.len(),
        ));
    }
    stats.site_files = site.len();

    let summary = format!(
        "rustproxy traffic dump, {}\r\n\r\n\
         records:            {}\r\n\
         with a response:    {}\r\n\
         request headers:    {} bytes\r\n\
         request bodies:     {} bytes\r\n\
         response headers:   {} bytes\r\n\
         response bodies:    {} bytes\r\n\
         site files:         {}\r\n{}\
         \r\n_records/<id>.http  each request and response in full\r\n\
         _records/index.csv  one line per record with its sizes\r\n\
         <host>/<path>       successful response bodies, laid out as the sites\r\n",
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        stats.records,
        stats.responses,
        stats.req_header_bytes,
        stats.req_body_bytes,
        stats.resp_header_bytes,
        stats.resp_body_bytes,
        stats.site_files,
        if stats.skipped > 0 { format!("NOT INCLUDED:       {} records (zip entry limit)\r\n", stats.skipped) } else { String::new() },
    );
    files.insert("_records/index.csv".into(), csv.into_bytes());
    files.insert("_summary.txt".into(), summary.into_bytes());
    files.extend(site);
    (zip_stored(&files), stats)
}

/// Minimal ZIP writer (stored entries, UTF-8 names).
fn zip_stored(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    use chrono::{Datelike, Timelike};
    let now = chrono::Local::now();
    let time = ((now.hour() << 11) | (now.minute() << 5) | (now.second() / 2)) as u16;
    let date = (((now.year().clamp(1980, 2107) - 1980) as u32) << 9 | now.month() << 5 | now.day()) as u16;

    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let crc = crc32fast::hash(data);
        let offset = out.len() as u32;
        let mut fixed = Vec::new();
        fixed.extend_from_slice(&20u16.to_le_bytes()); // version needed
        fixed.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        fixed.extend_from_slice(&0u16.to_le_bytes()); // stored
        fixed.extend_from_slice(&time.to_le_bytes());
        fixed.extend_from_slice(&date.to_le_bytes());
        fixed.extend_from_slice(&crc.to_le_bytes());
        fixed.extend_from_slice(&(data.len() as u32).to_le_bytes());
        fixed.extend_from_slice(&(data.len() as u32).to_le_bytes());
        fixed.extend_from_slice(&(name.len() as u16).to_le_bytes());
        fixed.extend_from_slice(&0u16.to_le_bytes()); // extra length

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&fixed);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&fixed);
        central.extend_from_slice(&[0u8; 10]); // comment len, disk, attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // disk numbers
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/* ------------------------------ Tests ------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> (Arc<Recorder>, H1Session) {
        let rec = Arc::new(Recorder::new(64 * 1024 * 1024));
        let meta = ConnMeta {
            client: "10.0.0.2:5000".into(),
            server: "93.184.216.34:443".into(),
            scheme: "https",
            default_host: "fallback.test".into(),
        };
        (rec.clone(), H1Session::new(rec, meta))
    }

    /// Feed in awkward slices to prove the parser is split-agnostic.
    fn drip(feed: &mut dyn FnMut(&[u8]), data: &[u8], step: usize) {
        for chunk in data.chunks(step) {
            feed(chunk);
        }
    }

    #[test]
    fn parses_keepalive_chunked_and_content_length() {
        for step in [1, 3, 7, 4096] {
            let (rec, mut s) = session();
            let req = b"POST /login?next=%2F HTTP/1.1\r\nHost: example.com\r\nContent-Length: 9\r\n\r\nuser=a&p=\
                        GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n";
            let resp = b"HTTP/1.1 100 Continue\r\n\r\n\
                         HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n\
                         5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n\
                         HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope";
            drip(&mut |d| s.client_data(d), req, step);
            drip(&mut |d| s.server_data(d), resp, step);

            let flows = rec.snapshot("");
            assert_eq!(flows.len(), 2, "step {step}");
            let a = &flows[0];
            assert_eq!((a.method.as_str(), a.host.as_str(), a.path.as_str()), ("POST", "example.com", "/login?next=%2F"));
            assert_eq!(a.req_body, b"user=a&p=");
            assert_eq!(a.status, Some(200));
            assert_eq!(a.resp_body, b"hello world", "chunk framing must be removed");
            assert_eq!(a.state, "done");
            assert_eq!(a.url(), "https://example.com/login?next=%2F");
            let b = &flows[1];
            assert_eq!((b.status, b.resp_body.as_slice(), b.state), (Some(404), &b"nope"[..], "done"));
        }
    }

    #[test]
    fn head_304_until_close_and_abort() {
        let (rec, mut s) = session();
        s.client_data(b"HEAD /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\nGET /c HTTP/1.0\r\n\r\nGET /d HTTP/1.1\r\n\r\n");
        // HEAD advertises a length but sends no body; 304 likewise.
        s.server_data(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n");
        s.server_data(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n");
        s.server_data(b"HTTP/1.0 200 OK\r\n\r\nbody-until-");
        s.server_data(b"close");
        drop(s);
        let flows = rec.snapshot("");
        assert_eq!(flows[0].host, "fallback.test");
        assert_eq!((flows[0].state, flows[0].resp_size), ("done", 0));
        assert_eq!((flows[1].state, flows[1].status), ("done", Some(304)));
        assert_eq!((flows[2].state, flows[2].resp_body.as_slice()), ("done", &b"body-until-close"[..]));
        assert_eq!(flows[3].state, "aborted", "request with no response");
    }

    #[test]
    fn upgrade_and_garbage_stop_parsing() {
        let (rec, mut s) = session();
        s.client_data(b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n");
        s.server_data(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
        s.client_data(b"\x81\x05hello GET /not-a-request HTTP/1.1\r\n\r\n");
        s.server_data(b"\x81\x05world");
        let flows = rec.snapshot("");
        assert_eq!(flows.len(), 1);
        assert_eq!((flows[0].state, flows[0].status), ("upgraded", Some(101)));

        let (rec, mut s) = session();
        s.client_data(b"\x00\x01\x02 binary protocol \r\n\r\n");
        s.client_data(b"GET / HTTP/1.1\r\n\r\n");
        assert!(rec.snapshot("").is_empty());
    }

    #[test]
    fn pause_keeps_pairing_and_absolute_targets_split() {
        let (rec, mut s) = session();
        rec.set_recording(false);
        s.client_data(b"GET /skipped HTTP/1.1\r\nHost: h\r\n\r\n");
        rec.set_recording(true);
        s.client_data(b"GET http://plain.test:8080/x?y=1 HTTP/1.1\r\nHost: ignored\r\n\r\n");
        s.server_data(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
        s.server_data(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB");
        let flows = rec.snapshot("");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].resp_body, b"B", "second response belongs to the second request");
        assert_eq!(flows[0].url(), "http://plain.test:8080/x?y=1");
    }

    #[test]
    fn store_is_bounded_and_poll_is_incremental() {
        let rec = Arc::new(Recorder::new(1024 * 1024));
        let meta = ConnMeta { client: "c".into(), server: "s".into(), scheme: "http", default_host: "h".into() };
        let mut first = None;
        for i in 0..5 {
            let f = rec.begin(&meta, "GET", &format!("/{i}"), "HTTP/1.1", vec![]).unwrap();
            rec.set_response(&f, 200, "OK", "HTTP/1.1", vec![]);
            rec.append(&f, true, &vec![b'x'; 400 * 1024]);
            rec.finish(&f, "done");
            first.get_or_insert(f);
        }
        let all = rec.poll(0);
        assert!(all["stored_bytes"].as_u64().unwrap() <= 1024 * 1024);
        assert_eq!(all["count"], 2, "oldest flows evicted to fit the budget");
        assert_eq!(all["first_id"], 4);
        // Late data for an evicted flow is counted but not stored again.
        let f = first.unwrap();
        rec.append(&f, true, b"late");
        assert!(f.lock().unwrap().resp_body.is_empty());

        let rev = all["rev"].as_u64().unwrap();
        assert!(rec.poll(rev)["flows"].as_array().unwrap().is_empty());
        let g = rec.begin(&meta, "GET", "/new", "HTTP/1.1", vec![]).unwrap();
        assert_eq!(rec.poll(rev)["flows"].as_array().unwrap().len(), 1);
        rec.finish(&g, "done");
        rec.finish(&g, "aborted");
        let id = g.lock().unwrap().id;
        assert_eq!(rec.get(id).unwrap().state, "done", "first outcome wins");

        let epoch = rec.poll(0)["epoch"].as_u64().unwrap();
        rec.clear();
        let cleared = rec.poll(0);
        assert_eq!((cleared["count"].as_u64(), cleared["stored_bytes"].as_u64()), (Some(0), Some(0)));
        assert_ne!(cleared["epoch"].as_u64().unwrap(), epoch);
    }

    #[test]
    fn bodies_are_decoded_for_viewing_and_export() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"<html>hi</html>").unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(decode_body("gzip", &gz), b"<html>hi</html>");
        assert_eq!(decode_body("identity", b"raw"), b"raw");
        assert_eq!(decode_body("zstd", b"raw"), b"raw", "unknown coding is passed through");
        assert_eq!(decode_body("gzip", b"not gzip"), b"not gzip");

        let flow = |path: &str, ctype: &str, enc: &str, body: &[u8]| Flow {
            id: 1,
            scheme: "https".into(),
            host: "site.test".into(),
            method: "GET".into(),
            path: path.into(),
            status: Some(200),
            state: "done",
            resp_headers: vec![("Content-Type".into(), ctype.into()), ("Content-Encoding".into(), enc.into())],
            resp_body: body.to_vec(),
            ..Flow::default()
        };
        let page = flow("/", "text/html; charset=utf-8", "gzip", &gz);
        let img = flow("/img/a.png?v=2", "image/png", "", &[0x89, b'P', b'N', b'G', 0xff]);
        let api = flow("/api/../../etc/items", "application/json", "", b"{}");
        let mut failed = flow("/missing", "text/html", "", b"nope");
        failed.status = Some(404);

        assert_eq!(dump_path(&page), "site.test/index.html");
        assert_eq!(dump_path(&img), "site.test/img/a.png_v=2.png");
        assert_eq!(dump_path(&api), "site.test/api/etc/items.json", "no path traversal");

        let mut flows = vec![page, img, api, failed];
        for (i, f) in flows.iter_mut().enumerate() {
            f.id = i as u64 + 1;
        }
        let (zip, stats) = export_site_zip(&flows);
        assert_eq!(&zip[..4], b"PK\x03\x04");
        assert!(find(&zip, b"site.test/index.html<html>hi</html>").is_some(), "stored decoded");
        assert!(find(&zip, b"site.test/missing.html").is_none(), "error responses are not site files");
        assert!(find(&zip, b"_records/000004.http").is_some(), "every flow gets a record");
        assert!(find(&zip, b"_summary.txt").is_some());
        assert_eq!(stats.records, 4);
        assert_eq!(stats.responses, 4);
        assert_eq!(stats.site_files, 3);
        assert_eq!(stats.resp_body_bytes, flows.iter().map(|f| f.resp_size).sum::<u64>());
        let eocd = &zip[zip.len() - 22..];
        assert_eq!(&eocd[..4], b"PK\x05\x06");
        // 3 site files + 4 records + index.csv + _summary.txt
        assert_eq!(u16::from_le_bytes([eocd[10], eocd[11]]), 9);

        let har = export_har(&flows);
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0]["request"]["url"], "https://site.test/");
        assert_eq!(entries[0]["response"]["content"]["text"], "<html>hi</html>");
        assert_eq!(entries[1]["response"]["content"]["encoding"], "base64");
        assert_eq!(entries[1]["request"]["queryString"][0]["name"], "v");
    }
}
