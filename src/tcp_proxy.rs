use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};

use tracing::{debug, error, info, warn};

use crate::conn_tracker::ConnectionTracker;
use crate::connection_cache::ConnectionCache;
use crate::lb::LoadBalancer;
use crate::stats::StatsCollector;

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::tcprelay::proxy_listener::ProxyListener;

/* ---------- Optional socket2 for portable TCP keepalive ---------- */
#[cfg(any(unix, windows))]
use socket2::{SockRef, TcpKeepalive};
use socket2::{Domain, Protocol, Socket, Type};

/* ------------------------------ Config ------------------------------ */

const REPORT_INTERVAL_SECS: u64 = 30; // periodic reporter interval
const RECENT_WINDOW: StdDuration = StdDuration::from_secs(5 * 60); // 5 minutes

/// How long a connection may sit completely idle before the first TCP
/// keepalive probe. Must be shorter than typical NAT/firewall idle timeouts
/// (often 30–120s); 20s keeps the mapping warm without excess probes.
const TCP_KEEPALIVE_TIME: StdDuration = StdDuration::from_secs(20);
/// Interval between successive keepalive probes after the first.
const TCP_KEEPALIVE_INTERVAL: StdDuration = StdDuration::from_secs(10);
/// Give up after this many unanswered probes (~50s total dead-peer detect:
/// 20 + 10*3).
const TCP_KEEPALIVE_RETRIES: u32 = 3;
/// Linux-only: max time unacknowledged data may sit on the wire before the
/// connection is aborted. Covers blackhole paths where keepalive alone is
/// slow to notice. Slightly above keepidle+keepintvl*keepcnt.
#[cfg(target_os = "linux")]
const TCP_USER_TIMEOUT: StdDuration = StdDuration::from_secs(60);

/// Apply connection-stability socket options used by every relay path.
///
/// - `TCP_NODELAY` — avoid Nagle batching latency on interactive tunnels
/// - Aggressive TCP keepalive — refresh NAT mappings and detect dead peers
/// - `TCP_USER_TIMEOUT` (Linux) — abort stalled sends instead of hanging
///
/// Failures are ignored: some sandboxes/containers disallow these options.
pub(crate) fn tune_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);

    #[cfg(any(unix, windows))]
    {
        let ka = TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE_TIME)
            .with_interval(TCP_KEEPALIVE_INTERVAL)
            .with_retries(TCP_KEEPALIVE_RETRIES);
        let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = SockRef::from(stream).set_tcp_user_timeout(Some(TCP_USER_TIMEOUT));
    }
}

/* ------------------------------ TcpProxy ------------------------------ */

pub struct TcpProxy {
    bind_addr: String,
    target_addr: String,
    cache: ConnectionCache,
    stats: Option<Arc<StatsCollector>>,
    active_connections: Arc<AtomicUsize>,
    max_connections: usize,

    // Accumulated traffic counters
    total_tx_bytes: Arc<AtomicU64>, // client -> server
    total_rx_bytes: Arc<AtomicU64>, // server -> client

    // Recent connections: (time, client_ip)
    recent_conns: Arc<std::sync::Mutex<Vec<(Instant, IpAddr)>>>,

    // For log context
    start_time: Instant,
    listen_port: Arc<AtomicUsize>, // set after bind()

    // Load balancer (None = single-target mode)
    lb: Option<Arc<LoadBalancer>>,

    // Server→client relay buffer size (duplex pipe capacity)
    buffer_size: usize,

    // Optional Shadowsocks listener encryption (password, cipher)
    // When set, SS replaces the plain TCP listener on the same port
    ss_config: Option<(String, CipherKind)>,

    // Separate SS listener on a different port (addr, password, cipher)
    // When set, SS runs on this port AND plain TCP runs on bind_addr
    ss_listen_config: Option<(String, String, CipherKind)>,

    // VMess listener on a separate port (addr, uuid_bytes)
    vmess_listen_config: Option<(String, [u8; 16])>,

    // Connection tracker for dashboard visibility
    conn_tracker: Option<Arc<ConnectionTracker>>,
}

impl TcpProxy {
    #[allow(dead_code)]
    pub fn new(bind_addr: &str, target_addr: &str, cache_size_bytes: usize, max_connections: usize, buffer_size: usize) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            stats: None,
            active_connections: Arc::new(AtomicUsize::new(0)),
            max_connections,
            total_tx_bytes: Arc::new(AtomicU64::new(0)),
            total_rx_bytes: Arc::new(AtomicU64::new(0)),
            recent_conns: Arc::new(std::sync::Mutex::new(Vec::with_capacity(1024))),
            start_time: Instant::now(),
            listen_port: Arc::new(AtomicUsize::new(0)),
            lb: None,
            buffer_size,
            ss_config: None,
            ss_listen_config: None,
            vmess_listen_config: None,
            conn_tracker: None,
        }
    }

    pub fn with_stats(
        bind_addr: &str,
        target_addr: &str,
        cache_size_bytes: usize,
        manager_addr: Option<SocketAddr>,
        max_connections: usize,
        buffer_size: usize,
    ) -> Self {
        let stats =
            manager_addr.map(|addr| Arc::new(StatsCollector::new("tcp", bind_addr, Some(addr))));
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            stats,
            active_connections: Arc::new(AtomicUsize::new(0)),
            max_connections,
            total_tx_bytes: Arc::new(AtomicU64::new(0)),
            total_rx_bytes: Arc::new(AtomicU64::new(0)),
            recent_conns: Arc::new(std::sync::Mutex::new(Vec::with_capacity(1024))),
            start_time: Instant::now(),
            listen_port: Arc::new(AtomicUsize::new(0)),
            lb: None,
            buffer_size,
            ss_config: None,
            ss_listen_config: None,
            vmess_listen_config: None,
            conn_tracker: None,
        }
    }

    pub fn with_lb(
        bind_addr: &str,
        lb: Arc<LoadBalancer>,
        cache_size_bytes: usize,
        manager_addr: Option<SocketAddr>,
        max_connections: usize,
        buffer_size: usize,
    ) -> Self {
        let stats =
            manager_addr.map(|addr| Arc::new(StatsCollector::new("tcp-lb", bind_addr, Some(addr))));
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: String::new(), // unused in LB mode
            cache: ConnectionCache::new(cache_size_bytes),
            stats,
            active_connections: Arc::new(AtomicUsize::new(0)),
            max_connections,
            total_tx_bytes: Arc::new(AtomicU64::new(0)),
            total_rx_bytes: Arc::new(AtomicU64::new(0)),
            recent_conns: Arc::new(std::sync::Mutex::new(Vec::with_capacity(1024))),
            start_time: Instant::now(),
            listen_port: Arc::new(AtomicUsize::new(0)),
            lb: Some(lb),
            buffer_size,
            ss_config: None,
            ss_listen_config: None,
            vmess_listen_config: None,
            conn_tracker: None,
        }
    }

    pub fn set_ss_config(&mut self, password: String, method: CipherKind) {
        self.ss_config = Some((password, method));
    }

    /// Configure a separate SS listener on a different port.
    /// Plain TCP will continue on `bind_addr`; SS will listen on `addr`.
    pub fn set_ss_listen_addr(&mut self, addr: String, password: String, method: CipherKind) {
        self.ss_listen_config = Some((addr, password, method));
    }

    /// Configure a VMess listener on a separate port.
    pub fn set_vmess_listen_addr(&mut self, addr: String, uuid: [u8; 16]) {
        self.vmess_listen_config = Some((addr, uuid));
    }

    pub fn set_conn_tracker(&mut self, tracker: Arc<ConnectionTracker>) {
        self.conn_tracker = Some(tracker);
    }

    #[allow(dead_code)]
    pub fn conn_tracker_ref(&self) -> Option<Arc<ConnectionTracker>> {
        self.conn_tracker.clone()
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /* ---------- Accessors for WebState sharing ---------- */

    pub fn active_connections_ref(&self) -> Arc<AtomicUsize> {
        self.active_connections.clone()
    }

    pub fn total_tx_ref(&self) -> Arc<AtomicU64> {
        self.total_tx_bytes.clone()
    }

    pub fn total_rx_ref(&self) -> Arc<AtomicU64> {
        self.total_rx_bytes.clone()
    }

    #[allow(dead_code)]
    pub fn load_balancer(&self) -> Option<Arc<LoadBalancer>> {
        self.lb.clone()
    }

    pub fn start_time(&self) -> Instant {
        self.start_time
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        self.listen_port
            .store(local_addr.port() as usize, Ordering::Relaxed);

        let (current_cache, max_cache) = self.cache.get_cache_stats().await;
        if let Some(ref lb) = self.lb {
            let backends: Vec<String> = lb.backends().iter().map(|b| b.addr.to_string()).collect();
            info!(
                "TCP LB proxy listening on {} -> [{}] ({} algo, cache: {}/{}KB, max connections: {})",
                local_addr,
                backends.join(", "),
                lb.algorithm().as_str(),
                current_cache / 1024,
                max_cache / 1024,
                self.max_connections
            );
        } else {
            info!(
                "TCP proxy listening on {} -> {} (cache: {}/{}KB, max connections: {})",
                local_addr,
                self.target_addr,
                current_cache / 1024,
                max_cache / 1024,
                self.max_connections
            );
        }

        // Start stats reporting if enabled
        if let Some(stats) = &self.stats {
            stats.clone().start_reporting().await;
        }

        // Periodic reporter (warn! with port + uptime + totals + last-5m IPs)
        self.spawn_periodic_reporter();

        // If separate SS port is configured, spawn SS listener as background task
        if let Some((ref ss_addr, ref password, method)) = self.ss_listen_config {
            let ss_addr = ss_addr.clone();
            let password = password.clone();
            let active_connections = self.active_connections.clone();
            let max_connections = self.max_connections;
            let recent_conns = self.recent_conns.clone();
            let cache = self.cache.clone();
            let stats = self.stats.clone();
            let total_tx_bytes = self.total_tx_bytes.clone();
            let total_rx_bytes = self.total_rx_bytes.clone();
            let buffer_size = self.buffer_size;
            let conn_tracker = self.conn_tracker.clone();
            let lb = self.lb.clone();

            tokio::spawn(async move {
                let ss_addr_parsed: SocketAddr = match ss_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        error!("Invalid SS listen address {}: {}", ss_addr, e);
                        return;
                    }
                };
                let context = Context::new_shared(ServerType::Server);
                let svr_cfg = match ServerConfig::new(ss_addr_parsed, password.as_str(), method) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Invalid SS config for separate listener: {}", e);
                        return;
                    }
                };
                let ss_listener = match ProxyListener::bind(context, &svr_cfg).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind SS listener on {}: {}", ss_addr, e);
                        return;
                    }
                };
                info!("SS listener on {} (method: {:?}) — standalone SS proxy", ss_addr, method);

                loop {
                    match ss_listener.accept().await {
                        Ok((stream, client_addr)) => {
                            let current = active_connections.load(Ordering::Relaxed);
                            if current >= max_connections {
                                warn!(
                                    "Connection limit reached ({}/{}), rejecting SS {}",
                                    current, max_connections, client_addr
                                );
                                drop(stream);
                                continue;
                            }

                            {
                                let mut v = recent_conns.lock().unwrap();
                                v.push((Instant::now(), client_addr.ip()));
                            }

                            let cache = cache.clone();
                            let stats = stats.clone();
                            let active_connections = active_connections.clone();
                            let total_tx_bytes = total_tx_bytes.clone();
                            let total_rx_bytes = total_rx_bytes.clone();
                            let tracker = conn_tracker.clone();
                            let lb = lb.clone();

                            active_connections.fetch_add(1, Ordering::Relaxed);

                            tokio::spawn(async move {
                                let conn_id = tracker.as_ref().map(|t: &Arc<ConnectionTracker>| t.next_conn_id());
                                let mut backend_ref: Option<Arc<crate::lb::Backend>> = None;
                                let outcome: Option<(u64, u64)> = {
                                    let mut stream = stream;
                                    // Keep the client TCP leg of the SS tunnel alive.
                                    tune_tcp_stream(stream.get_ref());
                                    let result = match stream.handshake().await {
                                        Ok(ss_target_addr) => {
                                            let target_addr = ss_target_addr.to_string();
                                            info!("SS CONNECT from {} to {}", client_addr, target_addr);

                                            if let Some(ref lb) = lb {
                                                match lb.next_backend() {
                                                    Some(backend) => {
                                                        let backend_addr = backend.addr.to_string();
                                                        if let (Some(t), Some(cid)) = (tracker.as_ref(), conn_id) {
                                                            t.add(cid, client_addr, target_addr.clone());
                                                        }
                                                        backend.stats.active_connections.fetch_add(1, Ordering::Relaxed);
                                                        backend.stats.total_connections.fetch_add(1, Ordering::Relaxed);
                                                        backend_ref = Some(backend);

                                                        let backend_for_kill = backend_ref.clone().unwrap();
                                                        match parse_host_port(&target_addr) {
                                                            Ok((host, port)) => {
                                                                match socks5_connect(&backend_addr, &host, port).await {
                                                                    Ok(outbound) => {
                                                                        let relay = relay_streams(
                                                                            stream, outbound, client_addr, &target_addr,
                                                                            total_tx_bytes, total_rx_bytes, buffer_size,
                                                                        );
                                                                        tokio::select! {
                                                                            r = relay => r,
                                                                            _ = backend_for_kill.wait_kill() => {
                                                                                warn!("SS conn {} dropped: backend {} marked unhealthy", client_addr, backend_addr);
                                                                                Err("backend marked unhealthy".into())
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        error!("SOCKS5 connect via {} to {} failed: {}", backend_addr, target_addr, e);
                                                                        Err(e)
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!("Failed to parse SS target {}: {}", target_addr, e);
                                                                Err(e)
                                                            }
                                                        }
                                                    }
                                                    None => {
                                                        warn!("All backends disabled, rejecting SS {}", client_addr);
                                                        Err("No backends available".into())
                                                    }
                                                }
                                            } else {
                                                // No LB — direct connect (original behavior)
                                                if let (Some(t), Some(cid)) = (tracker.as_ref(), conn_id) {
                                                    t.add(cid, client_addr, target_addr.clone());
                                                }
                                                TcpProxy::connect_and_relay(
                                                    stream, client_addr, target_addr,
                                                    cache, stats, total_tx_bytes, total_rx_bytes, buffer_size,
                                                ).await.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })
                                            }
                                        }
                                        Err(e) => {
                                            debug!("SS handshake failed from {}: {}", client_addr, e);
                                            Err(e.into())
                                        }
                                    };
                                    match result {
                                        Ok((tx, rx)) => Some((tx, rx)),
                                        Err(e) => {
                                            debug!("SS connection from {} error: {}", client_addr, e);
                                            None
                                        }
                                    }
                                };

                                if let (Some(t), Some(cid)) = (tracker.as_ref(), conn_id) {
                                    if let Some((tx, rx)) = outcome {
                                        t.update_bytes(cid, tx, rx);
                                    }
                                    t.remove(cid);
                                }

                                if let Some(ref b) = backend_ref {
                                    match outcome {
                                        Some((tx, rx)) => {
                                            b.stats.total_tx_bytes.fetch_add(tx, Ordering::Relaxed);
                                            b.stats.total_rx_bytes.fetch_add(rx, Ordering::Relaxed);
                                        }
                                        None => {
                                            b.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    b.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                                }

                                active_connections.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept SS connection: {}", e);
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });

            // Fall through to plain TCP listener below
        }

        // If VMess port is configured, spawn VMess listener as background task
        if let Some((ref vmess_addr, ref vmess_uuid)) = self.vmess_listen_config {
            let vmess_addr = vmess_addr.clone();
            let vmess_uuid = *vmess_uuid;
            let active_connections = self.active_connections.clone();
            let max_connections = self.max_connections;
            let recent_conns = self.recent_conns.clone();
            let total_tx_bytes = self.total_tx_bytes.clone();
            let total_rx_bytes = self.total_rx_bytes.clone();
            let buffer_size = self.buffer_size;
            let conn_tracker = self.conn_tracker.clone();
            let lb = self.lb.clone();

            tokio::spawn(async move {
                let vmess_listener = match TcpListener::bind(&vmess_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind VMess listener on {}: {}", vmess_addr, e);
                        return;
                    }
                };
                let vmess_server = Arc::new(crate::vmess::VMessServer::new(vec![vmess_uuid]));
                info!("VMess listener on {} — AEAD mode", vmess_addr);

                loop {
                    match vmess_listener.accept().await {
                        Ok((stream, client_addr)) => {
                            let current = active_connections.load(Ordering::Relaxed);
                            if current >= max_connections {
                                warn!(
                                    "Connection limit reached ({}/{}), rejecting VMess {}",
                                    current, max_connections, client_addr
                                );
                                drop(stream);
                                continue;
                            }

                            {
                                let mut v = recent_conns.lock().unwrap();
                                v.push((Instant::now(), client_addr.ip()));
                            }

                            let active_connections = active_connections.clone();
                            let total_tx_bytes = total_tx_bytes.clone();
                            let total_rx_bytes = total_rx_bytes.clone();
                            let tracker = conn_tracker.clone();
                            let lb = lb.clone();
                            let vmess_server = vmess_server.clone();

                            active_connections.fetch_add(1, Ordering::Relaxed);

                            tokio::spawn(async move {
                                // Keep the client TCP leg of the VMess tunnel alive.
                                tune_tcp_stream(&stream);
                                let conn_id = tracker.as_ref().map(|t: &Arc<ConnectionTracker>| t.next_conn_id());
                                let mut backend_ref: Option<Arc<crate::lb::Backend>> = None;
                                let outcome: Option<(u64, u64)> = {
                                    let result: Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> = match vmess_server.accept(stream).await {
                                        Ok((vmess_stream, target_addr)) => {
                                            info!("VMess CONNECT from {} to {}", client_addr, target_addr);

                                            if let Some(ref lb) = lb {
                                                match lb.next_backend() {
                                                    Some(backend) => {
                                                        let backend_addr = backend.addr.to_string();
                                                        if let (Some(t), Some(cid)) = (tracker.as_ref(), conn_id) {
                                                            t.add(cid, client_addr, target_addr.clone());
                                                        }
                                                        backend.stats.active_connections.fetch_add(1, Ordering::Relaxed);
                                                        backend.stats.total_connections.fetch_add(1, Ordering::Relaxed);
                                                        backend_ref = Some(backend);

                                                        let backend_for_kill = backend_ref.clone().unwrap();
                                                        match parse_host_port(&target_addr) {
                                                            Ok((host, port)) => {
                                                                match socks5_connect(&backend_addr, &host, port).await {
                                                                    Ok(outbound) => {
                                                                        // Convert VMess stream to AsyncRead+AsyncWrite halves
                                                                        let (vmess_read, vmess_write) = vmess_stream.into_async_rw();
                                                                        // Combine into a single stream for relay
                                                                        let combined = tokio::io::join(vmess_read, vmess_write);
                                                                        let relay = relay_streams(
                                                                            combined, outbound, client_addr, &target_addr,
                                                                            total_tx_bytes, total_rx_bytes, buffer_size,
                                                                        );
                                                                        tokio::select! {
                                                                            r = relay => r,
                                                                            _ = backend_for_kill.wait_kill() => {
                                                                                warn!("VMess conn {} dropped: backend {} marked unhealthy", client_addr, backend_addr);
                                                                                Err("backend marked unhealthy".into())
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        error!("SOCKS5 connect via {} to {} failed: {}", backend_addr, target_addr, e);
                                                                        Err(e)
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!("Failed to parse VMess target {}: {}", target_addr, e);
                                                                Err(e)
                                                            }
                                                        }
                                                    }
                                                    None => {
                                                        warn!("All backends disabled, rejecting VMess {}", client_addr);
                                                        Err("No backends available".into())
                                                    }
                                                }
                                            } else {
                                                warn!("VMess listener requires LB mode");
                                                Err("No LB configured for VMess".into())
                                            }
                                        }
                                        Err(e) => {
                                            debug!("VMess handshake failed from {}: {}", client_addr, e);
                                            Err(e)
                                        }
                                    };
                                    match result {
                                        Ok((tx, rx)) => Some((tx, rx)),
                                        Err(e) => {
                                            debug!("VMess connection from {} error: {}", client_addr, e);
                                            None
                                        }
                                    }
                                };

                                if let (Some(t), Some(cid)) = (tracker.as_ref(), conn_id) {
                                    if let Some((tx, rx)) = outcome {
                                        t.update_bytes(cid, tx, rx);
                                    }
                                    t.remove(cid);
                                }

                                if let Some(ref b) = backend_ref {
                                    match outcome {
                                        Some((tx, rx)) => {
                                            b.stats.total_tx_bytes.fetch_add(tx, Ordering::Relaxed);
                                            b.stats.total_rx_bytes.fetch_add(rx, Ordering::Relaxed);
                                        }
                                        None => {
                                            b.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    b.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                                }

                                active_connections.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept VMess connection: {}", e);
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });

            // Fall through to plain TCP listener below
        }

        if let Some((ref password, method)) = self.ss_config {
            // ---- Shadowsocks-encrypted listener ----
            // Drop the plain listener; ProxyListener will bind its own
            drop(listener);
            let context = Context::new_shared(ServerType::Server);
            let svr_cfg = ServerConfig::new(local_addr, password.as_str(), method)
                .map_err(|e| format!("Invalid SS config: {}", e))?;
            let ss_listener = ProxyListener::bind(context, &svr_cfg).await
                .map_err(|e| format!("Failed to bind SS listener: {}", e))?;
            info!("Accepting Shadowsocks connections (method: {:?})", method);

            loop {
                match ss_listener.accept().await {
                    Ok((stream, client_addr)) => {
                        let current = self.active_connections.load(Ordering::Relaxed);
                        if current >= self.max_connections {
                            warn!(
                                "Connection limit reached ({}/{}), rejecting {}",
                                current, self.max_connections, client_addr
                            );
                            drop(stream);
                            continue;
                        }

                        {
                            let mut v = self.recent_conns.lock().unwrap();
                            v.push((Instant::now(), client_addr.ip()));
                        }

                        let (target_addr, backend) = if let Some(ref lb) = self.lb {
                            match lb.next_backend() {
                                Some(b) => (b.addr.to_string(), Some(b)),
                                None => {
                                    warn!("All backends disabled, rejecting {}", client_addr);
                                    drop(stream);
                                    continue;
                                }
                            }
                        } else {
                            (self.target_addr.clone(), None)
                        };

                        let cache = self.cache.clone();
                        let stats = self.stats.clone();
                        let active_connections = self.active_connections.clone();
                        let total_tx_bytes = self.total_tx_bytes.clone();
                        let total_rx_bytes = self.total_rx_bytes.clone();
                        let buffer_size = self.buffer_size;
                        let tracker = self.conn_tracker.clone();

                        active_connections.fetch_add(1, Ordering::Relaxed);
                        if let Some(ref b) = backend {
                            b.stats.active_connections.fetch_add(1, Ordering::Relaxed);
                            b.stats.total_connections.fetch_add(1, Ordering::Relaxed);
                        }

                        tokio::spawn(async move {
                            let conn_id = tracker.as_ref().map(|t: &Arc<ConnectionTracker>| t.next_conn_id());
                            let outcome: Option<(u64, u64)> = {
                                let mut stream = stream;
                                // Keep the client TCP leg of the SS tunnel alive.
                                tune_tcp_stream(stream.get_ref());
                                let result = match stream.handshake().await {
                                    Ok(ss_target_addr) => {
                                        let ss_target = ss_target_addr.to_string();
                                        if let (Some(t), Some(cid)) = (tracker.as_ref(), conn_id) {
                                            t.add(cid, client_addr, ss_target);
                                        }
                                        Self::connect_and_relay(
                                            stream, client_addr, target_addr,
                                            cache, stats, total_tx_bytes, total_rx_bytes, buffer_size,
                                        ).await
                                    }
                                    Err(e) => {
                                        debug!("SS handshake failed from {}: {}", client_addr, e);
                                        Err(e.into())
                                    }
                                };
                                match result {
                                    Ok((tx, rx)) => Some((tx, rx)),
                                    Err(e) => {
                                        debug!("SS connection from {} error: {}", client_addr, e);
                                        None
                                    }
                                }
                            };

                            if let (Some(t), Some(cid)) = (tracker.as_ref(), conn_id) {
                                if let Some((tx, rx)) = outcome {
                                    t.update_bytes(cid, tx, rx);
                                }
                                t.remove(cid);
                            }

                            if let Some(ref b) = backend {
                                match outcome {
                                    Some((tx, rx)) => {
                                        b.stats.total_tx_bytes.fetch_add(tx, Ordering::Relaxed);
                                        b.stats.total_rx_bytes.fetch_add(rx, Ordering::Relaxed);
                                    }
                                    None => {
                                        b.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                b.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                            }
                            active_connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept SS connection: {}", e);
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        } else {
            // ---- Plain TCP listener with SO_REUSEPORT N-acceptor fan-out ----
            // Drop the original exclusively-bound listener so we can rebind
            // the same port with SO_REUSEPORT across N kernel-balanced sockets.
            drop(listener);

            let n_acceptors = std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1)
                .clamp(1, 16);

            let mut handles = Vec::with_capacity(n_acceptors);
            for i in 0..n_acceptors {
                let l = match make_reuseport_listener(local_addr) {
                    Ok(l) => l,
                    Err(e) => {
                        if i == 0 {
                            return Err(format!("Failed to bind plain TCP acceptor: {}", e).into());
                        }
                        warn!(
                            "Failed to bind acceptor #{} on {}: {} — continuing with {} acceptors",
                            i, local_addr, e, i
                        );
                        break;
                    }
                };

                let cache = self.cache.clone();
                let stats = self.stats.clone();
                let active_connections = self.active_connections.clone();
                let max_connections = self.max_connections;
                let default_target = self.target_addr.clone();
                let lb = self.lb.clone();
                let recent_conns = self.recent_conns.clone();
                let total_tx_bytes = self.total_tx_bytes.clone();
                let total_rx_bytes = self.total_rx_bytes.clone();
                let buffer_size = self.buffer_size;
                let tracker = self.conn_tracker.clone();

                handles.push(tokio::spawn(async move {
                    run_plain_accept_loop(
                        l,
                        cache,
                        stats,
                        active_connections,
                        max_connections,
                        default_target,
                        lb,
                        recent_conns,
                        total_tx_bytes,
                        total_rx_bytes,
                        buffer_size,
                        tracker,
                    )
                    .await;
                }));
            }
            info!(
                "Plain TCP accept fan-out: {} SO_REUSEPORT acceptors on {}",
                handles.len(),
                local_addr
            );

            for h in handles {
                let _ = h.await;
            }
            Ok(())
        }
    }

    fn spawn_periodic_reporter(&self) {
        let total_tx = self.total_tx_bytes.clone();
        let total_rx = self.total_rx_bytes.clone();
        let recent = self.recent_conns.clone();
        let start_time = self.start_time;
        let listen_port = self.listen_port.clone();

        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(REPORT_INTERVAL_SECS)).await;

                // Snapshot totals
                let tx = total_tx.load(Ordering::Relaxed);
                let rx = total_rx.load(Ordering::Relaxed);

                // Compute uptime (hours with two decimals)
                let uptime_h = Instant::now().duration_since(start_time).as_secs_f64() / 3600.0;

                // Build last-5m IP->count map and prune old entries
                let mut ip_counts: HashMap<IpAddr, usize> = HashMap::new();
                let now = Instant::now();
                {
                    let mut v = recent.lock().unwrap();
                    v.retain(|(t, _)| now.duration_since(*t) <= RECENT_WINDOW);
                    for (_t, ip) in v.iter() {
                        *ip_counts.entry(*ip).or_insert(0) += 1;
                    }
                }

                // Format compact IP list (cap to 10 entries + ellipsis)
                let mut parts: Vec<String> = ip_counts
                    .into_iter()
                    .map(|(ip, c)| format!("{}({})", ip, c))
                    .collect();
                parts.sort();
                if parts.len() > 10 {
                    parts.truncate(10);
                    parts.push("…".to_string());
                }

                // Count of unique IPs (excluding ellipsis)
                let unique_count = parts
                    .last()
                    .map(|s| if s == "…" { parts.len() - 1 } else { parts.len() })
                    .unwrap_or(0);

                warn!(
                    ":{} [uptime {:.2}h] Traffic totals: TX {:.2} MiB, RX {:.2} MiB | Last 5m unique IPs: {} [{}]",
                    listen_port.load(Ordering::Relaxed),
                    uptime_h,
                    bytes_to_mib(tx),
                    bytes_to_mib(rx),
                    unique_count,
                    parts.join(", ")
                );
            }
        });
    }

    pub async fn handle_connection_with_cache(
        inbound: TcpStream,
        client_addr: SocketAddr,
        target_addr: String,
        cache: ConnectionCache,
        stats: Option<Arc<StatsCollector>>,
        _active_connections: Arc<AtomicUsize>,
        total_tx_bytes: Arc<AtomicU64>,
        total_rx_bytes: Arc<AtomicU64>,
        buffer_size: usize,
    ) -> Result<(u64, u64), Box<dyn std::error::Error>> {
        // Keep both ends of the tunnel warm through NATs/firewalls and
        // detect dead peers promptly (see tune_tcp_stream).
        tune_tcp_stream(&inbound);

        Self::connect_and_relay(
            inbound, client_addr, target_addr, cache, stats,
            total_tx_bytes, total_rx_bytes, buffer_size,
        ).await
    }

    /// Generic relay: connect to target backend and pump data bidirectionally.
    /// Works with any inbound stream (plain TCP or decrypted SS).
    pub async fn connect_and_relay<S>(
        inbound: S,
        client_addr: SocketAddr,
        target_addr: String,
        cache: ConnectionCache,
        stats: Option<Arc<StatsCollector>>,
        total_tx_bytes: Arc<AtomicU64>,
        total_rx_bytes: Arc<AtomicU64>,
        buffer_size: usize,
    ) -> Result<(u64, u64), Box<dyn std::error::Error>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Create stats connection ID if stats are enabled
        let conn_id = if let Some(ref stats) = stats {
            Some(stats.new_connection(client_addr, target_addr.clone()).await)
        } else {
            None
        };

        // Get or create outbound
        let outbound = match cache.get_connection(&target_addr).await {
            Some(conn) => {
                debug!("Using cached connection for {} -> {}", client_addr, target_addr);
                conn
            }
            None => {
                debug!("Creating new connection for {} -> {}", client_addr, target_addr);
                match timeout(Duration::from_secs(10), crate::dns::tcp_connect(&target_addr)).await {
                    Ok(Ok(conn)) => conn,
                    Ok(Err(e)) => {
                        error!("Failed to connect to {}: {}", target_addr, e);
                        if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                            stats.close_connection(conn_id).await;
                        }
                        return Err(e.into());
                    }
                    Err(_) => {
                        error!("Connection timeout to {}", target_addr);
                        if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                            stats.close_connection(conn_id).await;
                        }
                        return Err("Connection timeout".into());
                    }
                }
            }
        };

        // Outbound TCP tuning (inbound already tuned by callers that own a
        // TcpStream; SS/VMess encrypted inbounds are not plain sockets).
        tune_tcp_stream(&outbound);

        debug!("Proxying connection from {} to {}", client_addr, target_addr);

        // Pump each direction independently; a broken direction tears the
        // other down after a bounded grace (see run_pumps).
        let _ = buffer_size;
        let (bytes_to_server, bytes_to_client, e_c2s, e_s2c) =
            run_pumps(inbound, outbound).await;

        if let Some(e) = e_c2s {
            debug!(
                "Client->Server ended with error after {} bytes for {}: {}",
                bytes_to_server, client_addr, e
            );
        }
        if let Some(e) = e_s2c {
            debug!(
                "Server->Client ended with error after {} bytes for {}: {}",
                bytes_to_client, client_addr, e
            );
        }

        // Global totals
        total_tx_bytes.fetch_add(bytes_to_server, Ordering::Relaxed);
        total_rx_bytes.fetch_add(bytes_to_client, Ordering::Relaxed);

        debug!(
            "Connection {} closed. Transferred {} bytes to server, {} bytes to client",
            client_addr, bytes_to_server, bytes_to_client
        );

        // External stats
        if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
            stats
                .update_connection(conn_id, bytes_to_server, bytes_to_client)
                .await;
            stats.close_connection(conn_id).await;
        }

        Ok((bytes_to_server, bytes_to_client))
    }
}

/* ---------------- SO_REUSEPORT acceptor helpers ---------------- */

/// Create a non-blocking TCP listener bound to `addr` with SO_REUSEADDR
/// (cross-platform) and SO_REUSEPORT (Unix). This lets multiple sockets
/// share the same port; the kernel hashes incoming connections across
/// listeners, removing the single-acceptor bottleneck on conn-rate.
fn make_reuseport_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    let std_listener: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_listener)
}

/// Accept loop body extracted from `TcpProxy::start`'s plain-TCP branch so
/// it can run inside N parallel acceptor tasks (one per SO_REUSEPORT socket).
async fn run_plain_accept_loop(
    listener: TcpListener,
    cache: ConnectionCache,
    stats: Option<Arc<StatsCollector>>,
    active_connections: Arc<AtomicUsize>,
    max_connections: usize,
    default_target_addr: String,
    lb: Option<Arc<LoadBalancer>>,
    recent_conns: Arc<std::sync::Mutex<Vec<(Instant, IpAddr)>>>,
    total_tx_bytes: Arc<AtomicU64>,
    total_rx_bytes: Arc<AtomicU64>,
    buffer_size: usize,
    conn_tracker: Option<Arc<ConnectionTracker>>,
) {
    loop {
        match listener.accept().await {
            Ok((inbound, client_addr)) => {
                let current = active_connections.load(Ordering::Relaxed);
                if current >= max_connections {
                    warn!(
                        "Connection limit reached ({}/{}), rejecting connection from {}",
                        current, max_connections, client_addr
                    );
                    drop(inbound);
                    continue;
                }

                {
                    let mut v = recent_conns.lock().unwrap();
                    v.push((Instant::now(), client_addr.ip()));
                }

                let (target_addr, backend) = if let Some(ref lb) = lb {
                    match lb.next_backend() {
                        Some(b) => (b.addr.to_string(), Some(b)),
                        None => {
                            warn!("All backends disabled, rejecting connection from {}", client_addr);
                            drop(inbound);
                            continue;
                        }
                    }
                } else {
                    (default_target_addr.clone(), None)
                };

                let cache_c = cache.clone();
                let stats_c = stats.clone();
                let active_c = active_connections.clone();
                let total_tx_c = total_tx_bytes.clone();
                let total_rx_c = total_rx_bytes.clone();
                let tracker = conn_tracker.clone();

                active_connections.fetch_add(1, Ordering::Relaxed);
                if let Some(ref b) = backend {
                    b.stats.active_connections.fetch_add(1, Ordering::Relaxed);
                    b.stats.total_connections.fetch_add(1, Ordering::Relaxed);
                }

                tokio::spawn(async move {
                    let conn_id = tracker.as_ref().map(|t: &Arc<ConnectionTracker>| {
                        let cid = t.next_conn_id();
                        t.add(cid, client_addr, String::new());
                        cid
                    });

                    let outcome: Option<(u64, u64)> = {
                        let target_for_log = target_addr.clone();
                        let relay = TcpProxy::handle_connection_with_cache(
                            inbound,
                            client_addr,
                            target_addr,
                            cache_c,
                            stats_c,
                            active_c.clone(),
                            total_tx_c,
                            total_rx_c,
                            buffer_size,
                        );
                        let result = match backend.clone() {
                            Some(b) => tokio::select! {
                                r = relay => r,
                                _ = b.wait_kill() => {
                                    warn!("TCP conn {} dropped: backend {} marked unhealthy", client_addr, target_for_log);
                                    Err("backend marked unhealthy".into())
                                }
                            },
                            None => relay.await,
                        };
                        match result {
                            Ok((tx, rx)) => Some((tx, rx)),
                            Err(e) => {
                                error!("Error handling connection from {}: {}", client_addr, e);
                                None
                            }
                        }
                    };

                    if let (Some(t), Some(cid)) = (tracker.as_ref(), conn_id) {
                        if let Some((tx, rx)) = outcome {
                            t.update_bytes(cid, tx, rx);
                        }
                        t.remove(cid);
                    }

                    if let Some(ref b) = backend {
                        match outcome {
                            Some((tx, rx)) => {
                                b.stats.total_tx_bytes.fetch_add(tx, Ordering::Relaxed);
                                b.stats.total_rx_bytes.fetch_add(rx, Ordering::Relaxed);
                            }
                            None => {
                                b.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        b.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                    }
                    active_c.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/* -------------------- SOCKS5 client connect -------------------- */

/// Upper bound on the whole SOCKS5 setup: TCP connect + auth + CONNECT
/// reply. Without this, a backend that accepts and then goes silent hangs
/// the client connection forever during setup.
#[cfg(not(test))]
const SOCKS5_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const SOCKS5_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

/// Connect to a SOCKS5 proxy and issue a CONNECT to `target_host:target_port`.
/// Returns the tunnelled TcpStream ready for data relay.
/// The entire handshake (not just the TCP connect) is bounded by
/// SOCKS5_HANDSHAKE_TIMEOUT.
async fn socks5_connect(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    timeout(
        SOCKS5_HANDSHAKE_TIMEOUT,
        socks5_connect_inner(proxy_addr, target_host, target_port),
    )
    .await
    .map_err(|_| format!("SOCKS5 handshake timeout to {}", proxy_addr))?
}

async fn socks5_connect_inner(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = crate::dns::tcp_connect(proxy_addr)
        .await
        .map_err(|e| format!("SOCKS5 connect failed to {}: {}", proxy_addr, e))?;

    // Auth negotiation: version 5, 1 method, no-auth
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 || buf[1] != 0x00 {
        return Err(format!("SOCKS5 auth failed: {:02x}{:02x}", buf[0], buf[1]).into());
    }

    // CONNECT request with domain address type (0x03)
    let host_bytes = target_host.as_bytes();
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.push(0x05); // version
    req.push(0x01); // CONNECT
    req.push(0x00); // reserved
    req.push(0x03); // domain
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xff) as u8);
    stream.write_all(&req).await?;

    // Read reply header: ver, rep, rsv, atyp
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT rejected: reply={:02x}", reply[1]).into());
    }

    // Drain the bound-address field
    match reply[3] {
        0x01 => { let mut skip = [0u8; 6]; stream.read_exact(&mut skip).await?; }     // IPv4 + port
        0x03 => {                                                                      // Domain + port
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => { let mut skip = [0u8; 18]; stream.read_exact(&mut skip).await?; }    // IPv6 + port
        other => return Err(format!("SOCKS5 unknown atyp: {:02x}", other).into()),
    }

    // Handshake succeeded — apply stability tuning for the long-lived tunnel.
    tune_tcp_stream(&stream);
    Ok(stream)
}

/// Parse "host:port" into (host, port). Handles `[ipv6]:port` too.
fn parse_host_port(addr: &str) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(bracket_end) = addr.rfind(']') {
        // [ipv6]:port
        let host = &addr[1..bracket_end];
        let port: u16 = addr[bracket_end + 2..].parse()?;
        return Ok((host.to_string(), port));
    }
    let colon = addr.rfind(':').ok_or("Missing port in address")?;
    let host = &addr[..colon];
    let port: u16 = addr[colon + 1..].parse()?;
    Ok((host.to_string(), port))
}

/// Relay bidirectionally between an inbound stream and an already-connected outbound.
async fn relay_streams<S>(
    inbound: S,
    outbound: TcpStream,
    client_addr: SocketAddr,
    target_label: &str,
    total_tx_bytes: Arc<AtomicU64>,
    total_rx_bytes: Arc<AtomicU64>,
    buffer_size: usize,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tune_tcp_stream(&outbound);

    debug!("Proxying SS via SOCKS5: {} -> {}", client_addr, target_label);

    let _ = buffer_size;
    let (bytes_to_server, bytes_to_client, e_c2s, e_s2c) = run_pumps(inbound, outbound).await;

    if let Some(e) = e_c2s {
        debug!("Client->Server error after {} bytes for {}: {}", bytes_to_server, client_addr, e);
    }
    if let Some(e) = e_s2c {
        debug!("Server->Client error after {} bytes for {}: {}", bytes_to_client, client_addr, e);
    }

    total_tx_bytes.fetch_add(bytes_to_server, Ordering::Relaxed);
    total_rx_bytes.fetch_add(bytes_to_client, Ordering::Relaxed);

    debug!("SS connection {} closed. TX {} B, RX {} B", client_addr, bytes_to_server, bytes_to_client);

    Ok((bytes_to_server, bytes_to_client))
}

/* -------------------------- Accurate pump -------------------------- */

/// How long the surviving direction may keep running after the other
/// direction died with an I/O error (broken peer). A clean EOF half-close
/// is NOT subject to this grace — it waits indefinitely, since protocols
/// may legitimately stream long responses after the client closes its
/// write side.
#[cfg(not(test))]
const HALF_CLOSE_GRACE: Duration = Duration::from_secs(30);
#[cfg(test)]
const HALF_CLOSE_GRACE: Duration = Duration::from_millis(500);

/// Copy from reader to writer with precise accounting into `total`.
/// - Returns None on EOF (after half-closing the writer).
/// - Returns Some(error) on I/O failure — after best-effort shutting down
///   the writer so the opposite peer sees EOF instead of hanging forever.
///
/// A failed `shutdown` after clean EOF is *not* treated as an error: peers
/// that already closed can return ENOTCONN/BrokenPipe, and misclassifying
/// that would trigger HALF_CLOSE_GRACE instead of waiting indefinitely for
/// the surviving direction (e.g. a long download after client FIN).
async fn pump<R, W>(mut r: R, mut w: W, total: &AtomicU64) -> Option<io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 256 * 1024];

    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => {
                let _ = w.shutdown().await;
                return None;
            }
            Ok(n) => n,
            Err(e) => {
                // Propagate the break: half-close the writer so the other
                // peer observes EOF and the opposite pump can finish.
                let _ = w.shutdown().await;
                return Some(e);
            }
        };

        if let Err(e) = w.write_all(&buf[..n]).await {
            // Best-effort half-close the other way isn't possible here (we
            // only hold one write half); the opposite pump is torn down via
            // HALF_CLOSE_GRACE in run_pumps.
            return Some(e);
        }

        total.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Run both relay directions to completion.
///
/// A direction ending in clean EOF lets the other run indefinitely
/// (legitimate half-close). A direction ending in an I/O error gives the
/// other only HALF_CLOSE_GRACE to drain before the relay is torn down —
/// this is what prevents half-broken connections (e.g. client RST with an
/// idle server) from leaking the task and both sockets forever.
///
/// Returns (bytes client->server, bytes server->client, c2s error, s2c error).
///
/// Shared by every relay path (plain TCP, SS/VMess LB, standalone SS, SOCKS5)
/// so they all get the same leak-free teardown: an abrupt close on one side
/// can never leave the other direction (and both sockets) hanging forever.
pub(crate) async fn run_pumps<S>(
    inbound: S,
    outbound: TcpStream,
) -> (u64, u64, Option<io::Error>, Option<io::Error>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tx = AtomicU64::new(0); // client -> server
    let rx = AtomicU64::new(0); // server -> client

    let (ri, wi) = tokio::io::split(inbound);
    let (ro, wo) = outbound.into_split();

    let c2s = pump(ri, wo, &tx);
    let s2c = pump(ro, wi, &rx);
    tokio::pin!(c2s, s2c);

    fn grace_expired() -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "relay torn down: opposite direction failed and drain grace expired",
        )
    }

    let (e_c2s, e_s2c) = tokio::select! {
        e1 = &mut c2s => {
            let e2 = if e1.is_some() {
                timeout(HALF_CLOSE_GRACE, &mut s2c)
                    .await
                    .unwrap_or_else(|_| Some(grace_expired()))
            } else {
                (&mut s2c).await
            };
            (e1, e2)
        }
        e2 = &mut s2c => {
            let e1 = if e2.is_some() {
                timeout(HALF_CLOSE_GRACE, &mut c2s)
                    .await
                    .unwrap_or_else(|_| Some(grace_expired()))
            } else {
                (&mut c2s).await
            };
            (e1, e2)
        }
    };

    (
        tx.load(Ordering::Relaxed),
        rx.load(Ordering::Relaxed),
        e_c2s,
        e_s2c,
    )
}

/* ------------------------------ Helpers ------------------------------ */

fn bytes_to_mib(b: u64) -> f64 {
    (b as f64) / (1024.0 * 1024.0)
}

/* ------------------------------ Tests ------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockTcpServer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tcp_proxy_basic_functionality() {
        let _ = tracing_subscriber::fmt::try_init();

        let mock_server = MockTcpServer::new().await.unwrap();
        let target_addr = mock_server.addr();
        tokio::spawn(mock_server.echo_server());

        let proxy = TcpProxy::new("127.0.0.1:0", &target_addr.to_string(), 128 * 1024, 10000, 16 * 1024 * 1024);
        // Use start() loop pattern from original tests: we emulate acceptor here
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((inbound, client_addr)) = listener.accept().await {
                    let target_addr = target_addr.to_string();
                    tokio::spawn(async move {
                        let cache = ConnectionCache::new(128 * 1024);
                        let active = Arc::new(AtomicUsize::new(0));
                        let total_tx = Arc::new(AtomicU64::new(0));
                        let total_rx = Arc::new(AtomicU64::new(0));
                        let _ = TcpProxy::handle_connection_with_cache(
                            inbound,
                            client_addr,
                            target_addr,
                            cache,
                            None,
                            active,
                            total_tx,
                            total_rx,
                            16 * 1024 * 1024,
                        )
                        .await;
                    });
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let msg = b"Hello, TCP Proxy!";
        client.write_all(msg).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);

        // ensure proxy is used, avoid dead-code warn
        assert_eq!(proxy.max_connections(), 10000);
    }

    #[tokio::test]
    async fn test_tcp_proxy_multiple_connections() {
        let _ = tracing_subscriber::fmt::try_init();

        let mock_server = MockTcpServer::new().await.unwrap();
        let target_addr = mock_server.addr();
        tokio::spawn(mock_server.echo_server());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((inbound, client_addr)) = listener.accept().await {
                    let target_addr = target_addr.to_string();
                    tokio::spawn(async move {
                        let cache = ConnectionCache::new(128 * 1024);
                        let active = Arc::new(AtomicUsize::new(0));
                        let total_tx = Arc::new(AtomicU64::new(0));
                        let total_rx = Arc::new(AtomicU64::new(0));
                        let _ = TcpProxy::handle_connection_with_cache(
                            inbound,
                            client_addr,
                            target_addr,
                            cache,
                            None,
                            active,
                            total_tx,
                            total_rx,
                            16 * 1024 * 1024,
                        )
                        .await;
                    });
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut handles = vec![];
        for i in 0..5 {
            let addr = proxy_addr;
            handles.push(tokio::spawn(async move {
                let mut c = TcpStream::connect(addr).await.unwrap();
                let msg = format!("Message {}", i);
                c.write_all(msg.as_bytes()).await.unwrap();
                let mut buf = [0u8; 1024];
                let n = c.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_tcp_proxy_large_data() {
        let _ = tracing_subscriber::fmt::try_init();

        let mock_server = MockTcpServer::new().await.unwrap();
        let target_addr = mock_server.addr();
        tokio::spawn(mock_server.echo_server());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((inbound, client_addr)) = listener.accept().await {
                    let target_addr = target_addr.to_string();
                    tokio::spawn(async move {
                        let cache = ConnectionCache::new(128 * 1024);
                        let active = Arc::new(AtomicUsize::new(0));
                        let total_tx = Arc::new(AtomicU64::new(0));
                        let total_rx = Arc::new(AtomicU64::new(0));
                        let _ = TcpProxy::handle_connection_with_cache(
                            inbound,
                            client_addr,
                            target_addr,
                            cache,
                            None,
                            active,
                            total_tx,
                            total_rx,
                            16 * 1024 * 1024,
                        )
                        .await;
                    });
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let test_data = vec![b'A'; 8192];

        client.write_all(&test_data).await.unwrap();

        let mut buffer = vec![0; 8192];
        let mut total_read = 0usize;
        while total_read < test_data.len() {
            let n = client.read(&mut buffer[total_read..]).await.unwrap();
            if n == 0 {
                break;
            }
            total_read += n;
        }

        assert_eq!(total_read, test_data.len());
        assert_eq!(&buffer[..total_read], test_data.as_slice());
    }

    /// Theory #3: if the client RSTs while the server stays idle, the relay
    /// must still terminate. With `tokio::join!` over two independent pumps,
    /// the failed client->server pump never tears down the server->client
    /// pump, so the relay task (and both sockets) leak forever.
    #[tokio::test]
    async fn relay_terminates_when_client_rsts_and_server_stays_idle() {
        let _ = tracing_subscriber::fmt::try_init();

        // Backend that accepts and then holds the socket open, never
        // reading, writing, or closing (worst-case idle peer).
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = server.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(3600)).await;
            drop(sock);
        });

        // Front listener standing in for the proxy acceptor.
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();

        let relay = tokio::spawn(async move {
            let (inbound, client_addr) = front.accept().await.unwrap();
            let _ = TcpProxy::connect_and_relay(
                inbound,
                client_addr,
                server_addr.to_string(),
                ConnectionCache::new(0),
                None,
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
                0,
            )
            .await;
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(b"x").await.unwrap();
        // Let the relay establish its outbound leg before breaking the client.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // SO_LINGER=0 makes the close emit RST instead of FIN.
        socket2::SockRef::from(&client)
            .set_linger(Some(StdDuration::from_secs(0)))
            .unwrap();
        drop(client);

        let done = tokio::time::timeout(Duration::from_secs(5), relay).await;
        assert!(
            done.is_ok(),
            "relay leaked: did not terminate within 5s after client RST with an idle server"
        );
    }

    /// A clean half-close (FIN) is NOT an error: the server must still be
    /// able to deliver its response after the client shuts down its write
    /// side, even when the response arrives later. Locks in that the leak
    /// fix only applies a teardown grace to *broken* directions.
    #[tokio::test]
    async fn clean_half_close_lets_late_server_data_through() {
        let _ = tracing_subscriber::fmt::try_init();

        // Backend: read until EOF, wait (longer than any teardown grace),
        // then send a response and close.
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = server.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let _ = sock.write_all(b"late response").await;
        });

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        tokio::spawn(async move {
            let (inbound, client_addr) = front.accept().await.unwrap();
            let _ = TcpProxy::connect_and_relay(
                inbound,
                client_addr,
                server_addr.to_string(),
                ConnectionCache::new(0),
                None,
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
                0,
            )
            .await;
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap(); // clean FIN, read side stays open

        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
            .await
            .expect("timed out waiting for late server response")
            .unwrap();
        assert_eq!(resp, b"late response");
    }

    /// Theory: `socks5_connect` only bounds the TCP connect, not the SOCKS5
    /// handshake — a backend that accepts and then goes silent hangs the
    /// client connection forever during setup.
    #[tokio::test]
    async fn socks5_connect_does_not_hang_on_unresponsive_backend() {
        let _ = tracing_subscriber::fmt::try_init();

        // Accepts the connection and never responds.
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (sock, _) = server.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(3600)).await;
            drop(sock);
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            socks5_connect(&server_addr, "example.com", 80),
        )
        .await;
        match result {
            Ok(inner) => assert!(inner.is_err(), "handshake against silent backend must fail"),
            Err(_) => panic!("socks5_connect hung >5s on an unresponsive backend"),
        }
    }
}
