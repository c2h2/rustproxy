use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use rand::Rng;
use serde::Serialize;
use tokio::sync::Notify;

/* ------------------------------ Algorithm ------------------------------ */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbAlgorithm {
    RoundRobin,
    Random,
}

impl LbAlgorithm {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "roundrobin" | "rr" => Ok(LbAlgorithm::RoundRobin),
            "random" | "rand" => Ok(LbAlgorithm::Random),
            _ => Err(format!(
                "Unknown load balancing algorithm '{}'. Use 'roundrobin' or 'random'.",
                s
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LbAlgorithm::RoundRobin => "roundrobin",
            LbAlgorithm::Random => "random",
        }
    }
}

/* ------------------------------ Backend Stats ------------------------------ */

pub struct BackendStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicUsize,
    pub total_tx_bytes: AtomicU64,
    pub total_rx_bytes: AtomicU64,
    pub total_errors: AtomicU64,
    /// Healthcheck response time in milliseconds (0 if error/timeout/never checked)
    pub hc_response_ms: AtomicU64,
    /// Healthcheck status: 0=unknown, 1=ok, 2=error, 3=timeout, 4=admin_disabled
    pub hc_status: AtomicU64,
    /// Last healthcheck epoch seconds (0=never)
    pub hc_last_check_epoch: AtomicU64,
    /// Consecutive healthcheck failures (reset on success)
    pub hc_consecutive_fails: AtomicU64,
}

impl BackendStats {
    pub fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            total_tx_bytes: AtomicU64::new(0),
            total_rx_bytes: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            hc_response_ms: AtomicU64::new(0),
            hc_status: AtomicU64::new(0),
            hc_last_check_epoch: AtomicU64::new(0),
            hc_consecutive_fails: AtomicU64::new(0),
        }
    }
}

/* ------------------------------ Backend ------------------------------ */

pub struct Backend {
    pub id: usize,
    pub addr: SocketAddr,
    pub enabled: AtomicBool,
    /// When true, the backend was manually disabled by an admin and health checks must not re-enable it.
    pub admin_disabled: AtomicBool,
    pub stats: BackendStats,
    /// Wakes every active relay pinned to this backend so they can tear down.
    /// Notify::notify_waiters wakes only currently-registered waiters, so a
    /// later relay (after the backend recovers) is unaffected.
    kill_notify: Arc<Notify>,
}

impl Backend {
    pub fn new(id: usize, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            enabled: AtomicBool::new(true),
            admin_disabled: AtomicBool::new(false),
            stats: BackendStats::new(),
            kill_notify: Arc::new(Notify::new()),
        }
    }

    /// Returns a future that resolves when this backend is asked to drop
    /// in-flight connections. Relay loops should race this against their
    /// copy futures via `tokio::select!`.
    pub async fn wait_kill(&self) {
        self.kill_notify.notified().await;
    }

    /// Wake every relay currently waiting on `wait_kill`. Called when the
    /// health check transitions a backend from enabled→disabled, or on
    /// admin disable. Newly-arriving relays after this call are unaffected.
    pub fn kill_active(&self) {
        self.kill_notify.notify_waiters();
    }
}

/* ------------------------------ Snapshot (serializable) ------------------------------ */

#[derive(Debug, Clone, Serialize)]
pub struct BackendSnapshot {
    pub id: usize,
    pub addr: String,
    pub enabled: bool,
    pub admin_disabled: bool,
    pub total_connections: u64,
    pub active_connections: usize,
    pub total_tx_bytes: u64,
    pub total_rx_bytes: u64,
    pub total_errors: u64,
    pub hc_response_ms: u64,
    pub hc_status: u64,
    pub hc_last_check_epoch: u64,
}

/* ------------------------------ LoadBalancer ------------------------------ */

pub struct LoadBalancer {
    backends: Vec<Arc<Backend>>,
    algorithm: LbAlgorithm,
    rr_counter: AtomicUsize,
}

impl LoadBalancer {
    /// Parse a comma-separated list of `host:port` addresses into backends.
    pub fn new(targets_csv: &str, algorithm: LbAlgorithm) -> Result<Self, String> {
        let mut backends = Vec::new();
        for (i, raw) in targets_csv.split(',').enumerate() {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let addr: SocketAddr = raw
                .parse()
                .map_err(|e| format!("Invalid backend address '{}': {}", raw, e))?;
            backends.push(Arc::new(Backend::new(i, addr)));
        }
        if backends.is_empty() {
            return Err("No valid backend addresses provided".to_string());
        }
        Ok(Self {
            backends,
            algorithm,
            rr_counter: AtomicUsize::new(0),
        })
    }

    /// Pick the next enabled backend according to the configured algorithm.
    /// Returns `None` if all backends are disabled.
    pub fn next_backend(&self) -> Option<Arc<Backend>> {
        let enabled: Vec<&Arc<Backend>> = self
            .backends
            .iter()
            .filter(|b| b.enabled.load(Ordering::Relaxed))
            .collect();

        if enabled.is_empty() {
            return None;
        }

        match self.algorithm {
            LbAlgorithm::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % enabled.len();
                Some(Arc::clone(enabled[idx]))
            }
            LbAlgorithm::Random => {
                let idx = rand::thread_rng().gen_range(0..enabled.len());
                Some(Arc::clone(enabled[idx]))
            }
        }
    }

    pub fn enable_backend(&self, id: usize) -> bool {
        if let Some(b) = self.backends.iter().find(|b| b.id == id) {
            b.admin_disabled.store(false, Ordering::Relaxed);
            b.enabled.store(true, Ordering::Relaxed);
            b.stats.hc_status.store(0, Ordering::Relaxed); // reset to unknown
            b.stats.hc_consecutive_fails.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn disable_backend(&self, id: usize) -> bool {
        if let Some(b) = self.backends.iter().find(|b| b.id == id) {
            b.admin_disabled.store(true, Ordering::Relaxed);
            b.enabled.store(false, Ordering::Relaxed);
            b.stats.hc_status.store(4, Ordering::Relaxed); // admin_disabled
            b.kill_active();
            true
        } else {
            false
        }
    }

    /// Produce a serializable snapshot of all backends.
    pub fn snapshot(&self) -> Vec<BackendSnapshot> {
        self.backends
            .iter()
            .map(|b| BackendSnapshot {
                id: b.id,
                addr: b.addr.to_string(),
                enabled: b.enabled.load(Ordering::Relaxed),
                admin_disabled: b.admin_disabled.load(Ordering::Relaxed),
                total_connections: b.stats.total_connections.load(Ordering::Relaxed),
                active_connections: b.stats.active_connections.load(Ordering::Relaxed),
                total_tx_bytes: b.stats.total_tx_bytes.load(Ordering::Relaxed),
                total_rx_bytes: b.stats.total_rx_bytes.load(Ordering::Relaxed),
                total_errors: b.stats.total_errors.load(Ordering::Relaxed),
                hc_response_ms: b.stats.hc_response_ms.load(Ordering::Relaxed),
                hc_status: b.stats.hc_status.load(Ordering::Relaxed),
                hc_last_check_epoch: b.stats.hc_last_check_epoch.load(Ordering::Relaxed),
            })
            .collect()
    }

    pub fn algorithm(&self) -> LbAlgorithm {
        self.algorithm
    }

    pub fn backends(&self) -> &[Arc<Backend>] {
        &self.backends
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// `kill_active()` must wake every task currently in `wait_kill()`,
    /// and a fresh `wait_kill()` registered after the notify must not
    /// see the previous notification (otherwise reused backends would
    /// kill new connections).
    #[tokio::test]
    async fn kill_active_wakes_only_current_waiters() {
        let backend = Arc::new(Backend::new(0, "127.0.0.1:1".parse().unwrap()));

        let b1 = backend.clone();
        let waiter = tokio::spawn(async move { b1.wait_kill().await });

        // Give the waiter a moment to register.
        tokio::time::sleep(Duration::from_millis(20)).await;
        backend.kill_active();

        tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("waiter did not wake on kill_active")
            .unwrap();

        // A new wait registered AFTER the notify must not fire spontaneously.
        let b2 = backend.clone();
        let late = tokio::spawn(async move { b2.wait_kill().await });
        let result = tokio::time::timeout(Duration::from_millis(100), late).await;
        assert!(
            result.is_err(),
            "wait_kill registered after notify should not have fired"
        );
    }

    #[tokio::test]
    async fn disable_backend_kills_active() {
        let lb = LoadBalancer::new("127.0.0.1:1", LbAlgorithm::RoundRobin).unwrap();
        let backend = lb.backends()[0].clone();

        let b1 = backend.clone();
        let waiter = tokio::spawn(async move { b1.wait_kill().await });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(lb.disable_backend(0));

        tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("disable_backend did not propagate kill")
            .unwrap();
    }
}
