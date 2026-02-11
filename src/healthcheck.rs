use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::lb::LoadBalancer;

/// Result of a single healthcheck probe.
enum HealthCheckResult {
    Ok(u64),       // response time in ms
    Error(String), // error message
    Timeout,       // overall 10s timeout exceeded
}

/// Perform an HTTP ping healthcheck against a backend.
///
/// Connects directly to `backend_addr`, sends a minimal HTTP GET, and
/// verifies the response starts with `HTTP/`. The entire operation is
/// wrapped in a 10s timeout.
async fn check_http_backend(backend_addr: &str) -> HealthCheckResult {
    let result = timeout(Duration::from_secs(10), async {
        let start = Instant::now();

        // 1. TCP connect to the backend
        let mut stream = TcpStream::connect(backend_addr).await.map_err(|e| {
            format!("TCP connect failed: {}", e)
        })?;

        // 2. Send minimal HTTP GET
        let http_req = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            backend_addr
        );
        stream.write_all(http_req.as_bytes()).await.map_err(|e| {
            format!("HTTP request write failed: {}", e)
        })?;

        // 3. Read enough to verify HTTP response
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
        info!("[healthcheck] Starting HTTP ping healthcheck loop (interval=60s)");

        loop {
            let backends = lb.backends();
            let count = backends.len();
            let mut handles = Vec::with_capacity(count);

            for backend in backends.iter() {
                let addr = backend.addr.to_string();
                handles.push(tokio::spawn(async move {
                    let result = check_http_backend(&addr).await;
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
                        backend.stats.hc_status.store(1, Ordering::Relaxed); // ok
                        if !backend.enabled.load(Ordering::Relaxed) {
                            backend.enabled.store(true, Ordering::Relaxed);
                            info!(
                                "[healthcheck] backend {} ({}) recovered, re-enabled ({}ms)",
                                i, addr, ms
                            );
                        } else {
                            info!("[healthcheck] backend {} ({}) OK ({}ms)", i, addr, ms);
                        }
                    }
                    HealthCheckResult::Error(msg) => {
                        backend.stats.hc_response_ms.store(0, Ordering::Relaxed);
                        backend.stats.hc_status.store(2, Ordering::Relaxed); // error
                        if backend.enabled.load(Ordering::Relaxed) {
                            backend.enabled.store(false, Ordering::Relaxed);
                            warn!(
                                "[healthcheck] backend {} ({}) FAILED: {}, disabled",
                                i, addr, msg
                            );
                        } else {
                            warn!(
                                "[healthcheck] backend {} ({}) still failing: {}",
                                i, addr, msg
                            );
                        }
                    }
                    HealthCheckResult::Timeout => {
                        backend.stats.hc_response_ms.store(0, Ordering::Relaxed);
                        backend.stats.hc_status.store(3, Ordering::Relaxed); // timeout
                        if backend.enabled.load(Ordering::Relaxed) {
                            backend.enabled.store(false, Ordering::Relaxed);
                            warn!(
                                "[healthcheck] backend {} ({}) TIMEOUT, disabled",
                                i, addr
                            );
                        } else {
                            warn!(
                                "[healthcheck] backend {} ({}) still timing out",
                                i, addr
                            );
                        }
                    }
                }
            }

            // Safety valve: if ALL backends failed, re-enable all
            if all_failed && count > 0 {
                warn!(
                    "[healthcheck] ALL {} backends failed! Re-enabling all as safety valve.",
                    count
                );
                for backend in backends.iter() {
                    backend.enabled.store(true, Ordering::Relaxed);
                }
            }

            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}
