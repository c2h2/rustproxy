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

/* ------------------------------ Config ------------------------------ */

const REPORT_INTERVAL_SECS: u64 = 30; // periodic reporter interval
const RECENT_WINDOW: StdDuration = StdDuration::from_secs(5 * 60); // 5 minutes

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
    recent_conns: Arc<tokio::sync::Mutex<Vec<(Instant, IpAddr)>>>,

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
            recent_conns: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(1024))),
            start_time: Instant::now(),
            listen_port: Arc::new(AtomicUsize::new(0)),
            lb: None,
            buffer_size,
            ss_config: None,
            ss_listen_config: None,
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
            recent_conns: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(1024))),
            start_time: Instant::now(),
            listen_port: Arc::new(AtomicUsize::new(0)),
            lb: None,
            buffer_size,
            ss_config: None,
            ss_listen_config: None,
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
            recent_conns: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(1024))),
            start_time: Instant::now(),
            listen_port: Arc::new(AtomicUsize::new(0)),
            lb: Some(lb),
            buffer_size,
            ss_config: None,
            ss_listen_config: None,
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
                                let recent = recent_conns.clone();
                                let ip = client_addr.ip();
                                tokio::spawn(async move {
                                    let mut v = recent.lock().await;
                                    v.push((Instant::now(), ip));
                                });
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

                                                        match parse_host_port(&target_addr) {
                                                            Ok((host, port)) => {
                                                                match socks5_connect(&backend_addr, &host, port).await {
                                                                    Ok(outbound) => {
                                                                        relay_streams(
                                                                            stream, outbound, client_addr, &target_addr,
                                                                            total_tx_bytes, total_rx_bytes, buffer_size,
                                                                        ).await
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
                            let recent = self.recent_conns.clone();
                            let ip = client_addr.ip();
                            tokio::spawn(async move {
                                let mut v = recent.lock().await;
                                v.push((Instant::now(), ip));
                            });
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
            // ---- Plain TCP listener ----
            loop {
                match listener.accept().await {
                    Ok((inbound, client_addr)) => {
                        let current = self.active_connections.load(Ordering::Relaxed);
                        if current >= self.max_connections {
                            warn!(
                                "Connection limit reached ({}/{}), rejecting connection from {}",
                                current, self.max_connections, client_addr
                            );
                            drop(inbound);
                            continue;
                        }

                        {
                            let recent = self.recent_conns.clone();
                            let ip = client_addr.ip();
                            tokio::spawn(async move {
                                let mut v = recent.lock().await;
                                v.push((Instant::now(), ip));
                            });
                        }

                        let (target_addr, backend) = if let Some(ref lb) = self.lb {
                            match lb.next_backend() {
                                Some(b) => (b.addr.to_string(), Some(b)),
                                None => {
                                    warn!("All backends disabled, rejecting connection from {}", client_addr);
                                    drop(inbound);
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
                            let conn_id = tracker.as_ref().map(|t: &Arc<ConnectionTracker>| {
                                let cid = t.next_conn_id();
                                t.add(cid, client_addr, String::new());
                                cid
                            });

                            let outcome: Option<(u64, u64)> = {
                                let result = Self::handle_connection_with_cache(
                                    inbound,
                                    client_addr,
                                    target_addr,
                                    cache,
                                    stats,
                                    active_connections.clone(),
                                    total_tx_bytes,
                                    total_rx_bytes,
                                    buffer_size,
                                )
                                .await;
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
                            active_connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
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
                    let mut v = recent.lock().await;
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
        // TCP-specific inbound tuning
        let _ = inbound.set_nodelay(true);
        #[cfg(any(unix, windows))]
        {
            let ka = TcpKeepalive::new().with_time(StdDuration::from_secs(60));
            let _ = SockRef::from(&inbound).set_tcp_keepalive(&ka);
        }

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
                match timeout(Duration::from_secs(10), TcpStream::connect(&target_addr)).await {
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

        // Outbound TCP tuning
        let _ = outbound.set_nodelay(true);
        #[cfg(any(unix, windows))]
        {
            let ka = TcpKeepalive::new().with_time(StdDuration::from_secs(60));
            let _ = SockRef::from(&outbound).set_tcp_keepalive(&ka);
        }

        info!("Proxying connection from {} to {}", client_addr, target_addr);

        // Split inbound (generic) and outbound (TcpStream)
        let (ri, wi) = tokio::io::split(inbound);
        let (ro, wo) = outbound.into_split();

        // Client→Server: direct pump (no buffering needed)
        let c2s = pump(ri, wo);

        // Server→Client: buffered via duplex pipe so reads from server
        // are decoupled from slow client writes
        let (duplex_w, duplex_r) = tokio::io::duplex(buffer_size);
        let s2buf = tokio::spawn(async move { pump(ro, duplex_w).await });
        let buf2c = pump(duplex_r, wi);

        let (r1, r_s2buf, r_buf2c) = tokio::join!(c2s, s2buf, buf2c);

        let (bytes_to_server, e1_opt) = match r1 {
            Ok(n) => (n, None),
            Err(pe) => (pe.bytes, Some(pe.source)),
        };
        let (_bytes_into_buf, e_s2buf) = match r_s2buf {
            Ok(Ok(n)) => (n, None),
            Ok(Err(pe)) => (pe.bytes, Some(pe.source)),
            Err(je) => (0, Some(io::Error::new(io::ErrorKind::Other, je))),
        };
        let (bytes_to_client, e_buf2c) = match r_buf2c {
            Ok(n) => (n, None),
            Err(pe) => (pe.bytes, Some(pe.source)),
        };

        if let Some(e) = e1_opt {
            debug!(
                "Client->Server ended with error after {} bytes for {}: {}",
                bytes_to_server, client_addr, e
            );
        }
        if let Some(e) = e_s2buf {
            debug!(
                "Server->Buffer ended with error for {}: {}",
                client_addr, e
            );
        }
        if let Some(e) = e_buf2c {
            debug!(
                "Buffer->Client ended with error after {} bytes for {}: {}",
                bytes_to_client, client_addr, e
            );
        }

        // Global totals
        total_tx_bytes.fetch_add(bytes_to_server, Ordering::Relaxed);
        total_rx_bytes.fetch_add(bytes_to_client, Ordering::Relaxed);

        info!(
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

/* -------------------- SOCKS5 client connect -------------------- */

/// Connect to a SOCKS5 proxy and issue a CONNECT to `target_host:target_port`.
/// Returns the tunnelled TcpStream ready for data relay.
async fn socks5_connect(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(proxy_addr))
        .await
        .map_err(|_| format!("SOCKS5 connect timeout to {}", proxy_addr))?
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
    let _ = outbound.set_nodelay(true);
    #[cfg(any(unix, windows))]
    {
        let ka = TcpKeepalive::new().with_time(StdDuration::from_secs(60));
        let _ = SockRef::from(&outbound).set_tcp_keepalive(&ka);
    }

    info!("Proxying SS via SOCKS5: {} -> {}", client_addr, target_label);

    let (ri, wi) = tokio::io::split(inbound);
    let (ro, wo) = outbound.into_split();

    let c2s = pump(ri, wo);
    let (duplex_w, duplex_r) = tokio::io::duplex(buffer_size);
    let s2buf = tokio::spawn(async move { pump(ro, duplex_w).await });
    let buf2c = pump(duplex_r, wi);

    let (r1, r_s2buf, r_buf2c) = tokio::join!(c2s, s2buf, buf2c);

    let (bytes_to_server, e1_opt) = match r1 {
        Ok(n) => (n, None),
        Err(pe) => (pe.bytes, Some(pe.source)),
    };
    let (_bytes_into_buf, e_s2buf) = match r_s2buf {
        Ok(Ok(n)) => (n, None),
        Ok(Err(pe)) => (pe.bytes, Some(pe.source)),
        Err(je) => (0, Some(io::Error::new(io::ErrorKind::Other, je))),
    };
    let (bytes_to_client, e_buf2c) = match r_buf2c {
        Ok(n) => (n, None),
        Err(pe) => (pe.bytes, Some(pe.source)),
    };

    if let Some(e) = e1_opt {
        debug!("Client->Server error after {} bytes for {}: {}", bytes_to_server, client_addr, e);
    }
    if let Some(e) = e_s2buf {
        debug!("Server->Buffer error for {}: {}", client_addr, e);
    }
    if let Some(e) = e_buf2c {
        debug!("Buffer->Client error after {} bytes for {}: {}", bytes_to_client, client_addr, e);
    }

    total_tx_bytes.fetch_add(bytes_to_server, Ordering::Relaxed);
    total_rx_bytes.fetch_add(bytes_to_client, Ordering::Relaxed);

    info!("SS connection {} closed. TX {} B, RX {} B", client_addr, bytes_to_server, bytes_to_client);

    Ok((bytes_to_server, bytes_to_client))
}

/* -------------------------- Accurate pump -------------------------- */

#[derive(Debug)]
struct PumpErr {
    bytes: u64,
    source: io::Error,
}

impl std::fmt::Display for PumpErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (after {} bytes)", self.source, self.bytes)
    }
}
impl std::error::Error for PumpErr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Copy from reader to writer with precise accounting.
/// - Ok(total) on EOF (after half-closing writer).
/// - Err(PumpErr { bytes: total_so_far, source }) on I/O error.
async fn pump<R, W>(mut r: R, mut w: W) -> Result<u64, PumpErr>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;

    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => {
                if let Err(e) = w.shutdown().await {
                    return Err(PumpErr { bytes: total, source: e });
                }
                return Ok(total);
            }
            Ok(n) => n,
            Err(e) => return Err(PumpErr { bytes: total, source: e }),
        };

        if let Err(e) = w.write_all(&buf[..n]).await {
            return Err(PumpErr { bytes: total, source: e });
        }

        total += n as u64;
    }
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
}
