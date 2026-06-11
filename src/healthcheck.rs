use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::lb::{Backend, LoadBalancer};

/// Consecutive probe failures required before a backend is disabled.
/// One bad sample (transient blip, slow probe target) must not take a
/// backend out of rotation.
pub const FAIL_THRESHOLD: u64 = 3;

/// What protocol the healthcheck speaks to the backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// Plain TCP connect — for raw TCP forwarding backends.
    TcpConnect,
    /// Full SOCKS5 handshake + HTTP GET — for SOCKS5 proxy backends
    /// (SS/VMess LB paths, or plain LB fronting a SOCKS5 farm).
    Socks5,
}

impl ProbeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProbeKind::TcpConnect => "tcp",
            ProbeKind::Socks5 => "socks5",
        }
    }
}

/// Result of a single healthcheck probe.
enum HealthCheckResult {
    Ok(u64),       // response time in ms
    Error(String), // error message
    Timeout,       // overall timeout exceeded
}

/// Plain TCP connect probe for raw-TCP backends. The previous SOCKS5-only
/// probe misclassified every healthy plain TCP backend as failed.
async fn check_tcp_backend(addr: &str) -> HealthCheckResult {
    let start = Instant::now();
    match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => HealthCheckResult::Ok(start.elapsed().as_millis() as u64),
        Ok(Err(e)) => HealthCheckResult::Error(format!("TCP connect failed: {}", e)),
        Err(_) => HealthCheckResult::Timeout,
    }
}

async fn probe_backend(addr: &str, kind: ProbeKind) -> HealthCheckResult {
    match kind {
        ProbeKind::TcpConnect => check_tcp_backend(addr).await,
        ProbeKind::Socks5 => check_socks5_backend(addr).await,
    }
}

/// Perform a SOCKS5 healthcheck against a proxy backend.
///
/// Connects to `proxy_addr`, performs a SOCKS5 handshake to CONNECT to
/// `google.com:80`, sends an HTTP GET, and verifies the response starts
/// with `HTTP/`. The entire operation is wrapped in a 10s timeout.
async fn check_socks5_backend(proxy_addr: &str) -> HealthCheckResult {
    let result = timeout(Duration::from_secs(10), async {
        let start = Instant::now();

        // 1. TCP connect to the SOCKS5 proxy
        let mut stream = TcpStream::connect(proxy_addr).await.map_err(|e| {
            format!("TCP connect failed: {}", e)
        })?;

        // 2. SOCKS5 greeting: version=5, 1 auth method, no-auth=0
        stream.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| {
            format!("greeting write failed: {}", e)
        })?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.map_err(|e| {
            format!("greeting read failed: {}", e)
        })?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            return Err(format!("bad greeting response: {:02x}{:02x}", resp[0], resp[1]));
        }

        // 3. SOCKS5 CONNECT to google.com:80
        //    [VER=05, CMD=01(connect), RSV=00, ATYP=03(domain), LEN=0a, "google.com", PORT=0050]
        let domain = b"google.com";
        let mut connect_req = Vec::with_capacity(4 + 1 + domain.len() + 2);
        connect_req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
        connect_req.push(domain.len() as u8);
        connect_req.extend_from_slice(domain);
        connect_req.extend_from_slice(&[0x00, 0x50]); // port 80
        stream.write_all(&connect_req).await.map_err(|e| {
            format!("connect request write failed: {}", e)
        })?;

        // 4. Read SOCKS5 CONNECT response
        //    [VER, REP, RSV, ATYP, BND.ADDR..., BND.PORT(2)]
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr).await.map_err(|e| {
            format!("connect response read failed: {}", e)
        })?;
        if hdr[1] != 0x00 {
            return Err(format!("SOCKS5 CONNECT failed with rep={:02x}", hdr[1]));
        }

        // Drain bound address based on ATYP
        match hdr[3] {
            0x01 => {
                // IPv4: 4 bytes addr + 2 bytes port
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await.map_err(|e| {
                    format!("drain IPv4 addr failed: {}", e)
                })?;
            }
            0x03 => {
                // Domain: 1 byte len + domain + 2 bytes port
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await.map_err(|e| {
                    format!("drain domain len failed: {}", e)
                })?;
                let mut buf = vec![0u8; len_buf[0] as usize + 2];
                stream.read_exact(&mut buf).await.map_err(|e| {
                    format!("drain domain addr failed: {}", e)
                })?;
            }
            0x04 => {
                // IPv6: 16 bytes addr + 2 bytes port
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await.map_err(|e| {
                    format!("drain IPv6 addr failed: {}", e)
                })?;
            }
            other => {
                return Err(format!("unknown ATYP {:02x}", other));
            }
        }

        // 5. Send HTTP GET through the tunnel
        let http_req = b"GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
        stream.write_all(http_req).await.map_err(|e| {
            format!("HTTP request write failed: {}", e)
        })?;

        // 6. Read enough to verify HTTP response
        let mut resp_buf = [0u8; 128];
        let n = stream.read(&mut resp_buf).await.map_err(|e| {
            format!("HTTP response read failed: {}", e)
        })?;
        if n < 5 || !resp_buf[..n].starts_with(b"HTTP/") {
            return Err("response does not start with HTTP/".to_string());
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;
        Ok(elapsed_ms)
    })
    .await;

    match result {
        Ok(Ok(ms)) => HealthCheckResult::Ok(ms),
        Ok(Err(msg)) => HealthCheckResult::Error(msg),
        Err(_) => HealthCheckResult::Timeout,
    }
}

/// Apply one probe result to a backend's health state. Returns true if the
/// probe was OK.
///
/// - OK → reset fail counter, re-enable (unless admin-disabled)
/// - Error/Timeout → bump fail counter; disable only after FAIL_THRESHOLD
///   consecutive failures, and NEVER kill in-flight connections — the
///   backend just stops receiving new ones and existing streams drain on
///   their own. (`kill_active` remains admin-disable-only.)
fn apply_health_result(backend: &Backend, idx: usize, addr: &str, result: HealthCheckResult) -> bool {
    match result {
        HealthCheckResult::Ok(ms) => {
            backend.stats.hc_response_ms.store(ms, Ordering::Relaxed);
            backend.stats.hc_consecutive_fails.store(0, Ordering::Relaxed);
            if backend.admin_disabled.load(Ordering::Relaxed) {
                // Keep hc_status=4 (admin_disabled), don't re-enable
                info!(
                    "[healthcheck] backend {} ({}) healthy ({}ms) but kept disabled by admin",
                    idx, addr, ms
                );
            } else if !backend.enabled.load(Ordering::Relaxed) {
                backend.stats.hc_status.store(1, Ordering::Relaxed);
                backend.enabled.store(true, Ordering::Relaxed);
                info!(
                    "[healthcheck] backend {} ({}) recovered, re-enabled ({}ms)",
                    idx, addr, ms
                );
            } else {
                backend.stats.hc_status.store(1, Ordering::Relaxed);
                info!("[healthcheck] backend {} ({}) OK ({}ms)", idx, addr, ms);
            }
            true
        }
        HealthCheckResult::Error(_) | HealthCheckResult::Timeout => {
            let (status, what) = match &result {
                HealthCheckResult::Error(msg) => (2, format!("FAILED: {}", msg)),
                _ => (3, "TIMEOUT".to_string()),
            };
            backend.stats.hc_response_ms.store(0, Ordering::Relaxed);
            let fails = backend
                .stats
                .hc_consecutive_fails
                .fetch_add(1, Ordering::Relaxed)
                + 1;

            if backend.admin_disabled.load(Ordering::Relaxed) {
                // Keep hc_status=4 (admin_disabled)
                info!(
                    "[healthcheck] backend {} ({}) admin-disabled, probe {}",
                    idx, addr, what
                );
            } else {
                backend.stats.hc_status.store(status, Ordering::Relaxed);
                if backend.enabled.load(Ordering::Relaxed) {
                    if fails >= FAIL_THRESHOLD {
                        backend.enabled.store(false, Ordering::Relaxed);
                        warn!(
                            "[healthcheck] backend {} ({}) {} — disabled after {} consecutive failures (in-flight connections drain, none killed)",
                            idx, addr, what, fails
                        );
                    } else {
                        warn!(
                            "[healthcheck] backend {} ({}) {} ({}/{} consecutive failures, still enabled)",
                            idx, addr, what, fails, FAIL_THRESHOLD
                        );
                    }
                } else {
                    warn!(
                        "[healthcheck] backend {} ({}) still failing: {}",
                        idx, addr, what
                    );
                }
            }
            false
        }
    }
}

/// Spawn a background task that probes all backends every 60 seconds.
///
/// - Initial 5s delay before the first check
/// - Each backend is probed concurrently via `tokio::spawn`
/// - OK → re-enable backend, update hc_response_ms
/// - Error/Timeout → disable after FAIL_THRESHOLD consecutive failures
///   (drain only — in-flight connections are never killed)
/// - If ALL backends fail, re-enable all (safety valve)
pub fn spawn_healthcheck_task(lb: Arc<LoadBalancer>, probe: ProbeKind) {
    tokio::spawn(async move {
        // Initial delay to let everything start up
        tokio::time::sleep(Duration::from_secs(5)).await;
        info!(
            "[healthcheck] Starting healthcheck loop (probe={}, interval=60s, fail threshold={})",
            probe.as_str(),
            FAIL_THRESHOLD
        );

        loop {
            let backends = lb.backends();
            let count = backends.len();
            let mut handles = Vec::with_capacity(count);

            for backend in backends.iter() {
                let addr = backend.addr.to_string();
                handles.push(tokio::spawn(async move {
                    let result = probe_backend(&addr, probe).await;
                    (result, addr)
                }));
            }

            let now_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut all_failed = true;

            for (i, handle) in handles.into_iter().enumerate() {
                let (result, addr) = match handle.await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("[healthcheck] task join error for backend {}: {}", i, e);
                        continue;
                    }
                };

                let backend = &backends[i];
                backend
                    .stats
                    .hc_last_check_epoch
                    .store(now_epoch, Ordering::Relaxed);

                if apply_health_result(backend, i, &addr, result) {
                    all_failed = false;
                }
            }

            // Safety valve: if ALL backends failed, re-enable all (except admin-disabled)
            if all_failed && count > 0 {
                let mut re_enabled = 0usize;
                let mut skipped = 0usize;
                for backend in backends.iter() {
                    if backend.admin_disabled.load(Ordering::Relaxed) {
                        skipped += 1;
                    } else {
                        backend.enabled.store(true, Ordering::Relaxed);
                        re_enabled += 1;
                    }
                }
                warn!(
                    "[healthcheck] ALL {} backends failed! Re-enabled {} as safety valve ({} kept admin-disabled).",
                    count, re_enabled, skipped
                );
            }

            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Theory #2: the healthcheck speaks SOCKS5, but plain-TCP LB mode
    /// forwards raw bytes — a perfectly healthy plain TCP backend (here:
    /// an echo server) fails the SOCKS5 probe. Combined with
    /// disable+kill_active, that breaks every in-flight stream.
    #[tokio::test]
    async fn socks5_probe_fails_against_healthy_plain_tcp_backend() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        match check_socks5_backend(&addr).await {
            HealthCheckResult::Ok(_) => {
                panic!("SOCKS5 probe unexpectedly succeeded against a plain TCP echo backend")
            }
            HealthCheckResult::Error(_) | HealthCheckResult::Timeout => {
                // Probe/protocol mismatch confirmed: a healthy raw-TCP backend
                // is reported as failed by the SOCKS5 healthcheck.
            }
        }
    }

    /// The TcpConnect probe kind correctly reports a plain TCP backend
    /// as healthy — this is what plain-TCP LB mode now uses by default.
    #[tokio::test]
    async fn tcp_probe_succeeds_against_plain_tcp_backend() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                drop(sock);
            }
        });

        match probe_backend(&addr, ProbeKind::TcpConnect).await {
            HealthCheckResult::Ok(_) => {}
            HealthCheckResult::Error(e) => panic!("TCP probe failed: {}", e),
            HealthCheckResult::Timeout => panic!("TCP probe timed out"),
        }
    }

    fn test_backend() -> Backend {
        Backend::new(0, "127.0.0.1:1".parse().unwrap())
    }

    /// A single failed probe must NOT disable a backend (no more
    /// one-blip mass disconnects). Only FAIL_THRESHOLD consecutive
    /// failures disable it.
    #[tokio::test]
    async fn single_failure_does_not_disable_threshold_does() {
        let b = test_backend();
        for n in 1..=FAIL_THRESHOLD {
            assert!(
                b.enabled.load(Ordering::Relaxed),
                "backend disabled after only {} failure(s)",
                n - 1
            );
            apply_health_result(&b, 0, "test", HealthCheckResult::Error("boom".into()));
        }
        assert!(
            !b.enabled.load(Ordering::Relaxed),
            "backend still enabled after {} consecutive failures",
            FAIL_THRESHOLD
        );
    }

    /// A successful probe resets the consecutive-failure counter.
    #[tokio::test]
    async fn success_resets_fail_counter() {
        let b = test_backend();
        apply_health_result(&b, 0, "test", HealthCheckResult::Error("boom".into()));
        apply_health_result(&b, 0, "test", HealthCheckResult::Timeout);
        apply_health_result(&b, 0, "test", HealthCheckResult::Ok(5));
        apply_health_result(&b, 0, "test", HealthCheckResult::Error("boom".into()));
        apply_health_result(&b, 0, "test", HealthCheckResult::Timeout);
        assert!(
            b.enabled.load(Ordering::Relaxed),
            "non-consecutive failures must not disable the backend"
        );
    }

    /// Disabling via healthcheck must DRAIN, not kill: in-flight relays
    /// waiting on `wait_kill` must not be woken. (Admin disable still kills.)
    #[tokio::test]
    async fn health_disable_drains_without_killing_in_flight() {
        let b = Arc::new(test_backend());

        let waiter = {
            let b = b.clone();
            tokio::spawn(async move { b.wait_kill().await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;

        for _ in 0..FAIL_THRESHOLD {
            apply_health_result(&b, 0, "test", HealthCheckResult::Timeout);
        }
        assert!(!b.enabled.load(Ordering::Relaxed), "backend should be disabled");

        let killed = tokio::time::timeout(Duration::from_millis(200), waiter).await;
        assert!(
            killed.is_err(),
            "healthcheck disable killed an in-flight connection; it must drain instead"
        );
    }

    /// Recovery: after a healthcheck disable, one OK probe re-enables.
    #[tokio::test]
    async fn ok_probe_reenables_health_disabled_backend() {
        let b = test_backend();
        for _ in 0..FAIL_THRESHOLD {
            apply_health_result(&b, 0, "test", HealthCheckResult::Error("down".into()));
        }
        assert!(!b.enabled.load(Ordering::Relaxed));

        apply_health_result(&b, 0, "test", HealthCheckResult::Ok(7));
        assert!(b.enabled.load(Ordering::Relaxed), "backend did not recover");
        assert_eq!(b.stats.hc_status.load(Ordering::Relaxed), 1);
    }

    /// Admin-disabled backends stay disabled regardless of probe results.
    #[tokio::test]
    async fn admin_disabled_backend_is_never_reenabled_by_probe() {
        let b = test_backend();
        b.admin_disabled.store(true, Ordering::Relaxed);
        b.enabled.store(false, Ordering::Relaxed);
        b.stats.hc_status.store(4, Ordering::Relaxed);

        apply_health_result(&b, 0, "test", HealthCheckResult::Ok(3));
        assert!(!b.enabled.load(Ordering::Relaxed));
        assert_eq!(b.stats.hc_status.load(Ordering::Relaxed), 4);
    }
}
