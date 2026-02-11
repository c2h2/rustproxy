use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};

use tracing::{debug, error, info, warn};

use crate::connection_cache::ConnectionCache;
use crate::lb::LoadBalancer;
use crate::stats::StatsCollector;

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
}

impl TcpProxy {
    #[allow(dead_code)]
    pub fn new(bind_addr: &str, target_addr: &str, cache_size_bytes: usize, max_connections: usize) -> Self {
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
        }
    }

    pub fn with_stats(
        bind_addr: &str,
        target_addr: &str,
        cache_size_bytes: usize,
        manager_addr: Option<SocketAddr>,
        max_connections: usize,
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
        }
    }

    pub fn with_lb(
        bind_addr: &str,
        lb: Arc<LoadBalancer>,
        cache_size_bytes: usize,
        manager_addr: Option<SocketAddr>,
        max_connections: usize,
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
        }
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

                    // Record recent connection for last-5m stats
                    {
                        let recent = self.recent_conns.clone();
                        let ip = client_addr.ip();
                        tokio::spawn(async move {
                            let mut v = recent.lock().await;
                            v.push((Instant::now(), ip));
                        });
                    }

                    // Resolve target: either from LB or fixed single target
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

                    active_connections.fetch_add(1, Ordering::Relaxed);

                    // Per-backend stats: increment active + total connections
                    if let Some(ref b) = backend {
                        b.stats.active_connections.fetch_add(1, Ordering::Relaxed);
                        b.stats.total_connections.fetch_add(1, Ordering::Relaxed);
                    }

                    tokio::spawn(async move {
                        let result = Self::handle_connection_with_cache(
                            inbound,
                            client_addr,
                            target_addr,
                            cache,
                            stats,
                            active_connections.clone(),
                            total_tx_bytes,
                            total_rx_bytes,
                        )
                        .await;

                        // Update per-backend stats
                        if let Some(ref b) = backend {
                            match &result {
                                Ok((tx, rx)) => {
                                    b.stats.total_tx_bytes.fetch_add(*tx, Ordering::Relaxed);
                                    b.stats.total_rx_bytes.fetch_add(*rx, Ordering::Relaxed);
                                }
                                Err(_) => {
                                    b.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            b.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                        }

                        if let Err(e) = result {
                            error!("Error handling connection from {}: {}", client_addr, e);
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
        mut inbound: TcpStream,
        client_addr: SocketAddr,
        target_addr: String,
        cache: ConnectionCache,
        stats: Option<Arc<StatsCollector>>,
        _active_connections: Arc<AtomicUsize>,
        total_tx_bytes: Arc<AtomicU64>,
        total_rx_bytes: Arc<AtomicU64>,
    ) -> Result<(u64, u64), Box<dyn std::error::Error>> {
        // Create stats connection ID if stats are enabled
        let conn_id = if let Some(ref stats) = stats {
            Some(stats.new_connection(client_addr, target_addr.clone()).await)
        } else {
            None
        };

        // Get or create outbound
        let mut outbound = match cache.get_connection(&target_addr).await {
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

        // Latency/health hints
        let _ = inbound.set_nodelay(true);
        let _ = outbound.set_nodelay(true);

        // Configure TCP keepalive (portable via socket2)
        #[cfg(any(unix, windows))]
        {
            let ka = TcpKeepalive::new().with_time(StdDuration::from_secs(60));
            let _ = SockRef::from(&inbound).set_tcp_keepalive(&ka);
            let _ = SockRef::from(&outbound).set_tcp_keepalive(&ka);
        }

        info!("Proxying connection from {} to {}", client_addr, target_addr);

        // Split and pump both directions
        let (ri, wi) = inbound.split();
        let (ro, wo) = outbound.split();

        let c2s = pump(ri, wo); // client -> server
        let s2c = pump(ro, wi); // server -> client

        let (r1, r2) = tokio::join!(c2s, s2c);

        let (bytes_to_server, e1_opt) = match r1 {
            Ok(n) => (n, None),
            Err(pe) => (pe.bytes, Some(pe.source)),
        };
        let (bytes_to_client, e2_opt) = match r2 {
            Ok(n) => (n, None),
            Err(pe) => (pe.bytes, Some(pe.source)),
        };

        if let Some(e) = e1_opt {
            debug!(
                "Client->Server ended with error after {} bytes for {}: {}",
                bytes_to_server, client_addr, e
            );
        }
        if let Some(e) = e2_opt {
            debug!(
                "Server->Client ended with error after {} bytes for {}: {}",
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
    let mut buf = vec![0u8; 16 * 1024];
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

        let proxy = TcpProxy::new("127.0.0.1:0", &target_addr.to_string(), 128 * 1024, 10000);
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
