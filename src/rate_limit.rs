//! Per-client-IP speed limiting (`--limit-per-ip-mb`).
//!
//! Every connection from the same client IP shares one token bucket, so
//! the limit bounds the IP's aggregate throughput (both directions
//! combined) across any number of parallel connections. Buckets refill
//! continuously at the configured rate with one second of burst; a pump
//! that overdraws sleeps off its debt before reading more.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

/// Bytes per second, decimal megabytes: `--limit-per-ip-mb 1` = 1_000_000 B/s.
pub const BYTES_PER_MB: f64 = 1_000_000.0;

/// Cap on one throttle sleep; debt beyond this carries over to the next.
const MAX_SLEEP: Duration = Duration::from_secs(30);

/// Stop tracking dead IPs once the registry grows past this.
const SWEEP_THRESHOLD: usize = 4096;

static LIMIT_BYTES_PER_SEC: OnceLock<f64> = OnceLock::new();

/// Set the global per-IP limit (bytes/sec). Call once at startup, before
/// any traffic; later calls are ignored.
pub fn set_limit_per_ip(bytes_per_sec: f64) {
    let _ = LIMIT_BYTES_PER_SEC.set(bytes_per_sec);
}

/// The configured per-IP limit in bytes/sec, if any.
pub fn limit_per_ip() -> Option<f64> {
    LIMIT_BYTES_PER_SEC.get().copied()
}

/// Token bucket shared by all connections from one client IP.
#[derive(Debug)]
pub struct IpRateLimiter {
    rate: f64,
    burst: f64,
    state: Mutex<Bucket>,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl IpRateLimiter {
    pub fn new(rate_bytes_per_sec: f64) -> Self {
        let rate = rate_bytes_per_sec.max(1.0);
        Self {
            rate,
            burst: rate, // one second of burst
            state: Mutex::new(Bucket {
                tokens: rate,
                last: Instant::now(),
            }),
        }
    }

    /// The bucket's refill rate in bytes/sec.
    pub fn rate_bytes_per_sec(&self) -> f64 {
        self.rate
    }

    /// Account `bytes` against the bucket, sleeping off any debt so the
    /// caller's average rate converges on the limit. Debt (not a queue)
    /// keeps this fair across however many pumps share the bucket.
    pub async fn throttle(&self, bytes: usize) {
        let wait = {
            let mut b = self.state.lock().unwrap();
            let now = Instant::now();
            let dt = now.duration_since(b.last).as_secs_f64();
            b.last = now;
            b.tokens = (b.tokens + dt * self.rate).min(self.burst);
            b.tokens -= bytes as f64;
            if b.tokens >= 0.0 {
                None
            } else {
                Some(Duration::from_secs_f64(-b.tokens / self.rate).min(MAX_SLEEP))
            }
        };
        if let Some(d) = wait {
            tokio::time::sleep(d).await;
        }
    }
}

static LIMITERS: Lazy<Mutex<HashMap<IpAddr, Arc<IpRateLimiter>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Limiter for `ip` when per-IP limiting is enabled (None otherwise).
/// Connections from the same IP get the same bucket for as long as any
/// of them is alive; idle entries are swept once the registry grows.
pub fn limiter_for(ip: IpAddr) -> Option<Arc<IpRateLimiter>> {
    let rate = limit_per_ip()?;
    let mut map = LIMITERS.lock().unwrap();
    if map.len() >= SWEEP_THRESHOLD && !map.contains_key(&ip) {
        map.retain(|_, l| Arc::strong_count(l) > 1);
    }
    Some(
        map.entry(ip)
            .or_insert_with(|| Arc::new(IpRateLimiter::new(rate)))
            .clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Within-burst traffic passes without sleeping.
    #[tokio::test]
    async fn burst_passes_untouched() {
        let l = IpRateLimiter::new(1_000_000.0);
        let t0 = Instant::now();
        l.throttle(500_000).await;
        assert!(t0.elapsed() < Duration::from_millis(100));
    }

    /// Overdrawing sleeps the debt off: 300 KB at 100 KB/s with a 100 KB
    /// burst owes ~2 s.
    #[tokio::test]
    async fn debt_is_slept_off() {
        let l = IpRateLimiter::new(100_000.0);
        let t0 = Instant::now();
        l.throttle(300_000).await;
        let dt = t0.elapsed();
        assert!(dt >= Duration::from_millis(1800), "slept only {dt:?}");
        assert!(dt < Duration::from_millis(3000), "slept {dt:?}");
    }

    /// Two pumps sharing one bucket split the rate between them.
    #[tokio::test]
    async fn shared_bucket_is_aggregate() {
        let l = Arc::new(IpRateLimiter::new(100_000.0));
        let t0 = Instant::now();
        let (a, b) = (l.clone(), l.clone());
        // 150 KB each = 300 KB total against a 100 KB burst → ~2 s debt.
        tokio::join!(a.throttle(150_000), b.throttle(150_000));
        assert!(t0.elapsed() >= Duration::from_millis(1800));
    }
}
