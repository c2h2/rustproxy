use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::lb::LoadBalancer;

/// Result of a single SOCKS5 healthcheck probe.
enum HealthCheckResult {
    Ok(u64),       // response time in ms
    Error(String), // error message
    Timeout,       // overall 10s timeout exceeded
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

/// Spawn a background task that probes all backends every 60 seconds.
///
/// - Initial 5s delay before the first check
/// - Each backend is probed concurrently via `tokio::spawn`
/// - OK → re-enable backend, update hc_response_ms
/// - Error/Timeout → disable backend, set hc_response_ms to 0
/// - If ALL backends fail, re-enable all (safety valve)
pub fn spawn_healthcheck_task(lb: Arc<LoadBalancer>) {
    tokio::spawn(async move {
        // Initial delay to let everything start up
        tokio::time::sleep(Duration::from_secs(5)).await;
        info!("[healthcheck] Starting SOCKS5 healthcheck loop (interval=60s)");

        loop {
            let backends = lb.backends();
            let count = backends.len();
            let mut handles = Vec::with_capacity(count);

            for backend in backends.iter() {
                let addr = backend.addr.to_string();
                handles.push(tokio::spawn(async move {
                    let result = check_socks5_backend(&addr).await;
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

                match result {
                    HealthCheckResult::Ok(ms) => {
                        all_failed = false;
                        backend.stats.hc_response_ms.store(ms, Ordering::Relaxed);
                        if backend.admin_disabled.load(Ordering::Relaxed) {
                            // Keep hc_status=4 (admin_disabled), don't re-enable
                            info!(
                                "[healthcheck] backend {} ({}) healthy ({}ms) but kept disabled by admin",
                                i, addr, ms
                            );
                        } else if !backend.enabled.load(Ordering::Relaxed) {
                            backend.stats.hc_status.store(1, Ordering::Relaxed);
                            backend.enabled.store(true, Ordering::Relaxed);
                            info!(
                                "[healthcheck] backend {} ({}) recovered, re-enabled ({}ms)",
                                i, addr, ms
                            );
                        } else {
                            backend.stats.hc_status.store(1, Ordering::Relaxed);
                            info!("[healthcheck] backend {} ({}) OK ({}ms)", i, addr, ms);
                        }
                    }
                    HealthCheckResult::Error(msg) => {
                        backend.stats.hc_response_ms.store(0, Ordering::Relaxed);
                        if backend.admin_disabled.load(Ordering::Relaxed) {
                            // Keep hc_status=4 (admin_disabled)
                            info!(
                                "[healthcheck] backend {} ({}) admin-disabled, hc error: {}",
                                i, addr, msg
                            );
                        } else if backend.enabled.load(Ordering::Relaxed) {
                            backend.stats.hc_status.store(2, Ordering::Relaxed);
                            backend.enabled.store(false, Ordering::Relaxed);
                            warn!(
                                "[healthcheck] backend {} ({}) FAILED: {}, disabled",
                                i, addr, msg
                            );
                        } else {
                            backend.stats.hc_status.store(2, Ordering::Relaxed);
                            warn!(
                                "[healthcheck] backend {} ({}) still failing: {}",
                                i, addr, msg
                            );
                        }
                    }
                    HealthCheckResult::Timeout => {
                        backend.stats.hc_response_ms.store(0, Ordering::Relaxed);
                        if backend.admin_disabled.load(Ordering::Relaxed) {
                            // Keep hc_status=4 (admin_disabled)
                            info!(
                                "[healthcheck] backend {} ({}) admin-disabled, hc timeout",
                                i, addr
                            );
                        } else if backend.enabled.load(Ordering::Relaxed) {
                            backend.stats.hc_status.store(3, Ordering::Relaxed);
                            backend.enabled.store(false, Ordering::Relaxed);
                            warn!(
                                "[healthcheck] backend {} ({}) TIMEOUT, disabled",
                                i, addr
                            );
                        } else {
                            backend.stats.hc_status.store(3, Ordering::Relaxed);
                            warn!(
                                "[healthcheck] backend {} ({}) still timing out",
                                i, addr
                            );
                        }
                    }
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
