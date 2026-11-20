//! CA download page for `--mitm` (`--http-interface` in http/socks5 modes).
//!
//! Serves the public CA certificate plus per-platform install instructions,
//! so a phone or another machine can fetch it straight from the proxy host.
//! Only the certificate is ever served — never `ca.key`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, ORIGIN,
    WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::mitm::Mitm;
use crate::mitm_record::{self, Recorder};

pub struct MitmWebState {
    pub mitm: Arc<Mitm>,
    /// Proxy mode (`http` or `socks5`), shown in the setup instructions.
    pub mode: String,
    /// The proxy's `--listen` address; its port is shown in the instructions.
    pub proxy_listen: String,
    /// The address this interface itself is bound to (`--http-interface`).
    pub web_listen: String,
    /// `user:password` for the traffic browser (`--mitm-web-auth`). Without
    /// it the traffic browser only answers loopback clients.
    pub auth: Option<String>,
}

type St = State<Arc<MitmWebState>>;

/// The CA page and certificate are public (devices need them before they
/// can do anything else); everything that exposes recorded traffic sits
/// behind [`guard`].
pub fn build_router(state: Arc<MitmWebState>) -> Router {
    let mut traffic = Router::new()
        .route("/traffic", get(traffic_page))
        .route("/api/flows", get(api_flows))
        .route("/api/flows/:id", get(api_flow))
        .route("/api/flows/:id/:side", get(api_body))
        .route("/api/recording", post(api_recording))
        .route("/api/clear", post(api_clear))
        .route("/export/har", get(export_har))
        .route("/export/site.zip", get(export_zip));
    if let Some(pcap) = state.mitm.pcap_path() {
        traffic = traffic.route_service("/export/pcap", tower_http::services::ServeFile::new(pcap));
    }
    // `route_layer`: guard the traffic routes only, not the router's 404 fallback.
    let traffic = traffic.route_layer(middleware::from_fn_with_state(state.clone(), guard));

    Router::new()
        .route("/", get(page))
        .route("/ca.crt", get(ca_pem))
        .route("/ca.pem", get(ca_pem))
        .route("/ca.cer", get(ca_der))
        .route("/trust-status", get(trust_status))
        .merge(traffic)
        .with_state(state)
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// "IPv4 · all interfaces" style description of a bind address.
fn describe_bind(addr: &str) -> String {
    match addr.parse::<SocketAddr>() {
        Ok(a) => {
            let ip = a.ip();
            let family = if ip.is_ipv4() { "IPv4" } else { "IPv6" };
            let scope = if ip.is_unspecified() {
                "all interfaces"
            } else if ip.is_loopback() {
                "this machine only"
            } else {
                "one interface"
            };
            format!("{family} · {scope}")
        }
        Err(_) => String::new(),
    }
}

/// The bar shared by both pages — navigation plus what is listening where.
/// Generated here, styles included, so the two pages cannot drift apart.
fn topbar(state: &MitmWebState, active: &str) -> String {
    let link = |href: &str, label: &str| {
        format!("<a href=\"{href}\"{}>{label}</a>", if href == active { " class=\"on\"" } else { "" })
    };
    let chip = |what: &str, addr: &str| {
        format!(
            "<span class=\"chip\"><b>{}</b> <span class=\"addr\">{}</span> <i>{}</i></span>",
            escape(what),
            escape(addr),
            describe_bind(addr)
        )
    };
    let proxy = if state.mode == "socks5" { "SOCKS5 proxy" } else { "HTTP proxy" };
    format!(
        r#"<style>
  .topbar {{ display: flex; flex-wrap: wrap; align-items: center; gap: 6px 18px; padding: 9px 14px;
    background: var(--panel); border-bottom: 1px solid var(--line);
    font: 14px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  .topbar .brand {{ font-weight: 700; font-size: 15px; color: var(--accent); }}
  .topbar nav {{ display: flex; gap: 4px; }}
  .topbar nav a {{ padding: 5px 11px; border-radius: 7px; color: var(--muted); text-decoration: none; }}
  .topbar nav a:hover {{ color: var(--text); }}
  .topbar nav a.on {{ color: var(--text); background: var(--code); font-weight: 600; }}
  .topbar .listening {{ display: flex; flex-wrap: wrap; gap: 6px; margin-left: auto; align-items: center; color: var(--muted); font-size: 12.5px; }}
  .topbar .chip {{ border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px; white-space: nowrap; }}
  .topbar .chip b {{ color: var(--text); font-weight: 600; }}
  .topbar .chip .addr {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--text); }}
  .topbar .chip i {{ font-style: normal; }}
</style>
<div class="topbar">
  <span class="brand">RustProxy</span>
  <nav>{}{}</nav>
  <span class="listening">Listening: {}{}</span>
</div>"#,
        link("/traffic", "Traffic"),
        link("/", "Install CA"),
        chip(proxy, &state.proxy_listen),
        chip("Web interface (HTTP)", &state.web_listen),
    )
}

fn deny(status: StatusCode, msg: &'static str) -> Response {
    (status, [(CACHE_CONTROL, "no-store")], msg).into_response()
}

/// Access control for recorded traffic, which contains credentials.
///
/// With `--mitm-web-auth` every request needs that HTTP Basic login. Without
/// it only loopback clients are served, and only when the `Host` header is
/// an IP literal or `localhost` — otherwise a web page could reach the API
/// through DNS rebinding. State-changing requests must also be same-origin.
async fn guard(State(state): St, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let host = req.headers().get(HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();

    if let Some(ref expected) = state.auth {
        let given = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok());
        // Compare without an early exit so timing does not leak a prefix.
        let ok = given.is_some_and(|g| {
            g.len() == expected.len() && g.iter().zip(expected.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        });
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                [(WWW_AUTHENTICATE, "Basic realm=\"rustproxy traffic\", charset=\"UTF-8\"")],
                "Authentication required",
            )
                .into_response();
        }
    } else {
        if !peer.ip().to_canonical().is_loopback() {
            return deny(
                StatusCode::FORBIDDEN,
                "The traffic browser shows decrypted traffic, so without a login it is only served to the \
                 machine running rustproxy (http://127.0.0.1:<port>/traffic). Start rustproxy with \
                 --mitm-web-auth user:password to open it from other machines.",
            );
        }
        let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host).trim_matches(['[', ']']);
        if name != "localhost" && name.parse::<std::net::IpAddr>().is_err() {
            return deny(StatusCode::FORBIDDEN, "Unexpected Host header");
        }
    }

    if req.method() != Method::GET && req.method() != Method::HEAD {
        if let Some(origin) = req.headers().get(ORIGIN).and_then(|v| v.to_str().ok()) {
            if origin.split("://").nth(1) != Some(host.as_str()) {
                return deny(StatusCode::FORBIDDEN, "Cross-origin request refused");
            }
        }
    }
    next.run(req).await
}

fn recorder(state: &MitmWebState) -> Result<Arc<Recorder>, Response> {
    state
        .mitm
        .recorder()
        .ok_or_else(|| deny(StatusCode::NOT_FOUND, "Traffic recording is not enabled"))
}

async fn traffic_page(State(state): St) -> impl IntoResponse {
    (
        [
            (CACHE_CONTROL, "no-store"),
            // Recorded content is only ever inserted as text, and nothing
            // outside this origin is loaded.
            (CONTENT_SECURITY_POLICY, "default-src 'self'; img-src blob:; style-src 'unsafe-inline'; script-src 'unsafe-inline'"),
        ],
        Html(include_str!("../static/mitm_traffic.html").replace("{{TOPBAR}}", &topbar(&state, "/traffic"))),
    )
}

async fn api_flows(State(state): St, Query(q): Query<HashMap<String, String>>) -> Response {
    let rec = match recorder(&state) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let since = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    ([(CACHE_CONTROL, "no-store")], Json(rec.poll(since))).into_response()
}

async fn api_flow(State(state): St, Path(id): Path<u64>) -> Response {
    match recorder(&state).map(|r| r.get(id)) {
        Ok(Some(flow)) => ([(CACHE_CONTROL, "no-store")], Json(flow.detail())).into_response(),
        Ok(None) => deny(StatusCode::NOT_FOUND, "No such flow"),
        Err(e) => e,
    }
}

/// A recorded body. Always served as an opaque download in a sandbox so
/// captured HTML or scripts can never run with access to this interface.
async fn api_body(State(state): St, Path((id, side)): Path<(u64, String)>, Query(q): Query<HashMap<String, String>>) -> Response {
    let response = match side.as_str() {
        "response" => true,
        "request" => false,
        _ => return deny(StatusCode::NOT_FOUND, "No such body"),
    };
    let flow = match recorder(&state).map(|r| r.get(id)) {
        Ok(Some(flow)) => flow,
        Ok(None) => return deny(StatusCode::NOT_FOUND, "No such flow"),
        Err(e) => return e,
    };
    let body = if q.contains_key("raw") {
        if response { flow.resp_body.clone() } else { flow.req_body.clone() }
    } else {
        flow.decoded_body(response)
    };
    let name = if response {
        mitm_record::dump_path(&flow).rsplit('/').next().unwrap_or("body").to_string()
    } else {
        format!("request-{id}.bin")
    };
    let disposition = if q.contains_key("download") {
        format!("attachment; filename=\"{}\"", name.replace(['"', '\\'], "_"))
    } else {
        "inline".to_string()
    };
    (
        [
            (CONTENT_TYPE, "application/octet-stream".to_string()),
            (X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'".to_string()),
            (CONTENT_DISPOSITION, disposition),
            (CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

async fn api_recording(State(state): St, Query(q): Query<HashMap<String, String>>) -> Response {
    match recorder(&state) {
        Ok(rec) => {
            rec.set_recording(q.get("on").map(|v| v != "0").unwrap_or(true));
            Json(serde_json::json!({"recording": rec.recording()})).into_response()
        }
        Err(e) => e,
    }
}

async fn api_clear(State(state): St) -> Response {
    match recorder(&state) {
        Ok(rec) => {
            rec.clear();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => e,
    }
}

fn export_name(ext: &str) -> String {
    format!(
        "attachment; filename=\"rustproxy-{}.{}\"",
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
        ext
    )
}

async fn export_har(State(state): St, Query(q): Query<HashMap<String, String>>) -> Response {
    let rec = match recorder(&state) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let filter = q.get("q").cloned().unwrap_or_default();
    // Decompression and serialisation of a large store is CPU work.
    let har = tokio::task::spawn_blocking(move || {
        serde_json::to_vec(&mitm_record::export_har(&rec.snapshot(&filter))).unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    (
        [
            (CONTENT_TYPE, "application/json".to_string()),
            (CONTENT_DISPOSITION, export_name("har")),
            (CACHE_CONTROL, "no-store".to_string()),
        ],
        har,
    )
        .into_response()
}

async fn export_zip(State(state): St, Query(q): Query<HashMap<String, String>>) -> Response {
    let rec = match recorder(&state) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let filter = q.get("q").cloned().unwrap_or_default();
    let (zip, s) = tokio::task::spawn_blocking(move || mitm_record::export_site_zip(&rec.snapshot(&filter)))
        .await
        .unwrap_or_default();
    // Counts for the traffic page, which fetches the dump and reports them.
    let counts = format!(
        "records={};responses={};req_headers={};req_bodies={};resp_headers={};resp_bodies={};site_files={};skipped={}",
        s.records,
        s.responses,
        s.req_header_bytes,
        s.req_body_bytes,
        s.resp_header_bytes,
        s.resp_body_bytes,
        s.site_files,
        s.skipped
    );
    (
        [
            (CONTENT_TYPE, "application/zip".to_string()),
            (CONTENT_DISPOSITION, export_name("zip")),
            (CACHE_CONTROL, "no-store".to_string()),
            (axum::http::HeaderName::from_static("x-dump-stats"), counts),
        ],
        zip,
    )
        .into_response()
}

async fn page(State(state): State<Arc<MitmWebState>>) -> impl IntoResponse {
    let port = state.proxy_listen.rsplit(':').next().unwrap_or("").to_string();
    let html = include_str!("../static/mitm_ca.html")
        .replace("{{TOPBAR}}", &topbar(&state, "/"))
        .replace("{{FINGERPRINT}}", &state.mitm.ca_fingerprint())
        .replace("{{MODE}}", &escape(&state.mode))
        .replace("{{PROXY_PORT}}", &escape(&port));
    ([(CACHE_CONTROL, "no-store")], Html(html))
}

/// PEM with the X.509 CA media type: iOS Safari offers it as a profile,
/// macOS opens it in Keychain Access, Windows in the certificate wizard.
async fn ca_pem(State(state): State<Arc<MitmWebState>>, ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    info!("mitm: CA certificate (.crt) downloaded by {} — fingerprint {}", peer.ip().to_canonical(), state.mitm.ca_fingerprint());
    (
        [
            (CONTENT_TYPE, "application/x-x509-ca-cert"),
            (CONTENT_DISPOSITION, "attachment; filename=\"rustproxy-ca.crt\""),
            (CACHE_CONTROL, "no-store"),
        ],
        state.mitm.ca_pem().to_string(),
    )
}

async fn ca_der(State(state): State<Arc<MitmWebState>>, ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    info!("mitm: CA certificate (.cer) downloaded by {} — fingerprint {}", peer.ip().to_canonical(), state.mitm.ca_fingerprint());
    (
        [
            (CONTENT_TYPE, "application/x-x509-ca-cert"),
            (CONTENT_DISPOSITION, "attachment; filename=\"rustproxy-ca.cer\""),
            (CACHE_CONTROL, "no-store"),
        ],
        state.mitm.ca_der(),
    )
}

/// What the proxy last saw from the *requesting* device: did it accept or
/// reject a certificate minted from this CA? Drives the self-test on the CA
/// page. Public, but only ever describes the caller's own address.
async fn trust_status(State(state): St, ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    let ip = peer.ip().to_canonical();
    let st = state.mitm.client_status(ip);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let ago = |t: Option<u64>| t.map(|t| now.saturating_sub(t));
    (
        [(CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "ip": ip.to_string(),
            "ok_ms_ago": ago(st.ok_ms),
            "fail_ms_ago": ago(st.fail_ms),
            "fail_reason": st.fail_reason,
        })),
    )
}

pub async fn serve(listener: TcpListener, state: Arc<MitmWebState>) -> std::io::Result<()> {
    axum::serve(listener, build_router(state).into_make_service_with_connect_info::<SocketAddr>()).await
}

pub async fn start(bind_addr: String, state: Arc<MitmWebState>) {
    match TcpListener::bind(&bind_addr).await {
        Ok(listener) => {
            info!("mitm: CA download page on http://{}/  traffic browser on http://{}/traffic", bind_addr, bind_addr);
            if let Err(e) = serve(listener, state).await {
                error!("mitm web interface error: {}", e);
            }
        }
        Err(e) => error!("Failed to bind mitm web interface on {}: {}", bind_addr, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::MitmConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn get(addr: std::net::SocketAddr, path: &str) -> Vec<u8> {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        out
    }

    fn body(resp: &[u8]) -> &[u8] {
        let at = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        &resp[at + 4..]
    }

    #[tokio::test]
    async fn serves_certificate_and_instructions_but_never_the_key() {
        let dir = std::env::temp_dir().join(format!("rustproxy-mitmweb-{}-{}", std::process::id(), rand::random::<u32>()));
        let mitm = Arc::new(
            Mitm::for_config(MitmConfig {
                ca_dir: dir.clone(),
                regen_ca: false,
                pcap: None,
                keylog: None,
                insecure: false,
                bypass: Vec::new(),
                record: true,
                store_mb: 16,
                keep_h2: false,
            })
            .unwrap(),
        );
        let state = Arc::new(MitmWebState { mitm: mitm.clone(), mode: "http".into(), proxy_listen: "0.0.0.0:8080".into(), web_listen: "[::]:8889".into(), auth: None });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { serve(listener, state).await.unwrap() });

        let on_disk = std::fs::read(dir.join("ca.crt")).unwrap();
        let crt = get(addr, "/ca.crt").await;
        let head = String::from_utf8_lossy(&crt).to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 200"));
        assert!(head.contains("content-type: application/x-x509-ca-cert"));
        assert_eq!(body(&crt), &on_disk[..]);

        let cer = get(addr, "/ca.cer").await;
        assert_eq!(body(&cer), &mitm.ca_der()[..]);
        assert_eq!(body(&cer)[0], 0x30, "DER certificate starts with a SEQUENCE");

        let page = get(addr, "/").await;
        let page = String::from_utf8_lossy(&page).into_owned();
        assert!(page.contains(&mitm.ca_fingerprint()));
        assert!(page.contains("iPhone") && page.contains("macOS") && page.contains("Windows"));
        assert!(!page.contains("{{"), "unfilled template placeholder");
        // Both pages say what is listening where, and on which IP family.
        assert!(page.contains("HTTP proxy") && page.contains("0.0.0.0:8080") && page.contains("IPv4 · all interfaces"));
        assert!(page.contains("[::]:8889") && page.contains("IPv6 · all interfaces"));

        let status = get(addr, "/trust-status").await;
        let status = String::from_utf8_lossy(&status).into_owned();
        assert!(status.contains("\"ip\":\"127.0.0.1\"") && status.contains("\"ok_ms_ago\":null"), "{status}");

        for path in ["/ca.key", "/ca.key.old", "/../ca.key"] {
            let resp = get(addr, path).await;
            assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 404"), "{path}");
            assert!(!resp.windows(11).any(|w| w == b"PRIVATE KEY"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn request(addr: SocketAddr, head: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("{head}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    async fn traffic_server(auth: Option<&str>) -> (SocketAddr, Arc<Mitm>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("rustproxy-mitmweb-{}-{}", std::process::id(), rand::random::<u32>()));
        let mitm = Arc::new(
            Mitm::for_config(MitmConfig {
                ca_dir: dir.clone(),
                regen_ca: false,
                pcap: None,
                keylog: None,
                insecure: false,
                bypass: Vec::new(),
                record: true,
                store_mb: 16,
                keep_h2: false,
            })
            .unwrap(),
        );
        let state = Arc::new(MitmWebState {
            mitm: mitm.clone(),
            mode: "http".into(),
            proxy_listen: "0.0.0.0:8080".into(),
            web_listen: "127.0.0.1:8889".into(),
            auth: auth.map(|a| a.to_string()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { serve(listener, state).await.unwrap() });
        (addr, mitm, dir)
    }

    fn record_one(mitm: &Mitm) {
        let rec = mitm.recorder().unwrap();
        let meta = mitm_record::ConnMeta {
            client: "10.0.0.2:5000".into(),
            server: "1.2.3.4:443".into(),
            scheme: "https",
            default_host: "site.test".into(),
        };
        let mut s = mitm_record::H1Session::new(rec, meta);
        s.client_data(b"GET /page HTTP/1.1\r\nHost: site.test\r\nCookie: sid=topsecret\r\n\r\n");
        s.server_data(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 29\r\n\r\n<script>alert(1)</script>body");
    }

    #[tokio::test]
    async fn traffic_api_lists_flows_and_serves_bodies_inertly() {
        let (addr, mitm, dir) = traffic_server(None).await;
        record_one(&mitm);
        let host = format!("Host: {addr}");

        let list = request(addr, &format!("GET /api/flows?since=0 HTTP/1.1\r\n{host}")).await;
        assert!(list.starts_with("HTTP/1.1 200"), "{list}");
        assert!(list.contains("\"host\":\"site.test\"") && list.contains("\"status\":200"));
        assert!(list.contains("\"client\":\"10.0.0.2:5000\"") && list.contains("\"server\":\"1.2.3.4:443\""));

        let detail = request(addr, &format!("GET /api/flows/1 HTTP/1.1\r\n{host}")).await;
        assert!(detail.contains("sid=topsecret") && detail.contains("https://site.test/page"));

        // Captured HTML must never be rendered as a page of this origin.
        let body = request(addr, &format!("GET /api/flows/1/response HTTP/1.1\r\n{host}")).await;
        let lower = body.to_ascii_lowercase();
        assert!(lower.contains("content-type: application/octet-stream"));
        assert!(lower.contains("x-content-type-options: nosniff"));
        assert!(lower.contains("content-security-policy: sandbox"));
        assert!(body.ends_with("<script>alert(1)</script>body"));

        let har = request(addr, &format!("GET /export/har?q=site.test HTTP/1.1\r\n{host}")).await;
        assert!(har.contains("\"version\":\"1.2\"") && har.contains("https://site.test/page"));
        let none = request(addr, &format!("GET /export/har?q=other.test HTTP/1.1\r\n{host}")).await;
        assert!(none.contains("\"entries\":[]"));
        let zip = request(addr, &format!("GET /export/site.zip HTTP/1.1\r\n{host}")).await;
        assert!(zip.contains("site.test/page.html"));

        let page = request(addr, &format!("GET /traffic HTTP/1.1\r\n{host}")).await;
        assert!(page.starts_with("HTTP/1.1 200") && page.contains("RustProxy traffic"));
        assert!(page.contains("127.0.0.1:8889") && page.contains("IPv4 · this machine only") && !page.contains("{{"));

        // Pause, then clear.
        let paused = request(addr, &format!("POST /api/recording?on=0 HTTP/1.1\r\n{host}\r\nContent-Length: 0")).await;
        assert!(paused.contains("\"recording\":false"));
        record_one(&mitm);
        assert_eq!(mitm.recorder().unwrap().snapshot("").len(), 1, "nothing recorded while paused");
        let cleared = request(addr, &format!("POST /api/clear HTTP/1.1\r\n{host}\r\nContent-Length: 0")).await;
        assert!(cleared.starts_with("HTTP/1.1 204"));
        assert!(mitm.recorder().unwrap().snapshot("").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn traffic_is_guarded_but_ca_page_stays_public() {
        // No login configured: loopback only, and no DNS-rebinding hosts or
        // cross-site writes.
        let (addr, mitm, dir) = traffic_server(None).await;
        record_one(&mitm);
        let rebind = request(addr, "GET /api/flows HTTP/1.1\r\nHost: evil.example:8889").await;
        assert!(rebind.starts_with("HTTP/1.1 403"), "{rebind}");
        assert!(!rebind.contains("site.test"));
        let csrf = request(
            addr,
            &format!("POST /api/clear HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://evil.example\r\nContent-Length: 0"),
        )
        .await;
        assert!(csrf.starts_with("HTTP/1.1 403"));
        assert_eq!(mitm.recorder().unwrap().snapshot("").len(), 1);
        let same = request(
            addr,
            &format!("POST /api/clear HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: 0"),
        )
        .await;
        assert!(same.starts_with("HTTP/1.1 204"));
        let _ = std::fs::remove_dir_all(&dir);

        // Login configured: required for traffic, not for the CA.
        let (addr, mitm, dir) = traffic_server(Some("admin:s3cret")).await;
        record_one(&mitm);
        for path in ["/traffic", "/api/flows", "/api/flows/1/response", "/export/har", "/export/site.zip"] {
            let anon = request(addr, &format!("GET {path} HTTP/1.1\r\nHost: x")).await;
            assert!(anon.starts_with("HTTP/1.1 401"), "{path}: {anon}");
            assert!(!anon.contains("topsecret") && !anon.contains("site.test"));
        }
        let wrong = base64::engine::general_purpose::STANDARD.encode("admin:s3cres");
        let bad = request(addr, &format!("GET /api/flows HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {wrong}")).await;
        assert!(bad.starts_with("HTTP/1.1 401"));
        let right = base64::engine::general_purpose::STANDARD.encode("admin:s3cret");
        let ok = request(addr, &format!("GET /api/flows HTTP/1.1\r\nHost: anything.example\r\nAuthorization: Basic {right}")).await;
        assert!(ok.starts_with("HTTP/1.1 200") && ok.contains("site.test"));
        let ca = request(addr, "GET /ca.crt HTTP/1.1\r\nHost: x").await;
        assert!(ca.starts_with("HTTP/1.1 200") && ca.contains("BEGIN CERTIFICATE"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
