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
    /// Sticky priority failover: `--target` order is priority 1,2,3,…
    /// Stay on the current backend while it is enabled. When it drops,
    /// walk to the next later target; wrap to the start only after the
    /// tail is exhausted. Never fail back to a recovered higher-priority
    /// backend while the current one still works.
    Failover,
}

impl LbAlgorithm {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "roundrobin" | "rr" => Ok(LbAlgorithm::RoundRobin),
            "random" | "rand" => Ok(LbAlgorithm::Random),
            "failover" | "priority" | "sticky" | "prio" => Ok(LbAlgorithm::Failover),
            _ => Err(format!(
                "Unknown load balancing algorithm '{}'. Use 'roundrobin', 'random', or 'failover'.",
                s
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LbAlgorithm::RoundRobin => "roundrobin",
            LbAlgorithm::Random => "random",
            LbAlgorithm::Failover => "failover",
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
    /// Failover sticky index. `usize::MAX` means "not yet chosen".
    sticky: AtomicUsize,
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
            sticky: AtomicUsize::new(usize::MAX),
        })
    }

    /// Pick the next enabled backend according to the configured algorithm.
    /// Returns `None` if all backends are disabled.
    ///
    /// Allocation-free: walks the backend slice and counts enabled entries
    /// instead of building a temporary `Vec` on every accept.
    pub fn next_backend(&self) -> Option<Arc<Backend>> {
        let n = self.backends.len();
        if n == 0 {
            return None;
        }

        // Count enabled without allocating.
        let mut enabled_count = 0usize;
        for b in &self.backends {
            if b.enabled.load(Ordering::Relaxed) {
                enabled_count += 1;
            }
        }
        if enabled_count == 0 {
            return None;
        }

        match self.algorithm {
            LbAlgorithm::Failover => self.next_failover(),
            LbAlgorithm::RoundRobin | LbAlgorithm::Random => {
                let pick = match self.algorithm {
                    LbAlgorithm::RoundRobin => {
                        self.rr_counter.fetch_add(1, Ordering::Relaxed) % enabled_count
                    }
                    LbAlgorithm::Random => rand::thread_rng().gen_range(0..enabled_count),
                    LbAlgorithm::Failover => unreachable!(),
                };

                let mut seen = 0usize;
                for b in &self.backends {
                    if !b.enabled.load(Ordering::Relaxed) {
                        continue;
                    }
                    if seen == pick {
                        return Some(Arc::clone(b));
                    }
                    seen += 1;
                }
                None
            }
        }
    }

    /// Sticky priority failover. Target list order is priority 1..N.
    /// Stay on the sticky backend while it is enabled. On failure, walk
    /// later targets first ("go next"); wrap to the head only after the
    /// tail is exhausted. A recovered higher-priority backend is ignored
    /// until the current one fails.
    fn next_failover(&self) -> Option<Arc<Backend>> {
        let n = self.backends.len();
        if n == 0 {
            return None;
        }
        let cur = self.sticky.load(Ordering::Relaxed);
        if cur < n && self.backends[cur].enabled.load(Ordering::Relaxed) {
            return Some(Arc::clone(&self.backends[cur]));
        }
        let start = if cur < n { (cur + 1) % n } else { 0 };
        for k in 0..n {
            let i = (start + k) % n;
            if self.backends[i].enabled.load(Ordering::Relaxed) {
                self.sticky.store(i, Ordering::Relaxed);
                return Some(Arc::clone(&self.backends[i]));
            }
        }
        None
    }

    /// Current sticky backend id for failover, or `None` if unset / not failover.
    pub fn sticky_id(&self) -> Option<usize> {
        if self.algorithm != LbAlgorithm::Failover {
            return None;
        }
        let cur = self.sticky.load(Ordering::Relaxed);
        if cur < self.backends.len() {
            Some(cur)
        } else {
            None
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

    /// Admin-disable a backend: stop sending **new** connections.
    /// In-flight streams **drain** (same as healthcheck). Use
    /// [`disable_backend_kill`] to also abort live relays.
    pub fn disable_backend(&self, id: usize) -> bool {
        self.disable_backend_inner(id, false)
    }

    /// Admin-disable and immediately kill every relay waiting on this backend.
    pub fn disable_backend_kill(&self, id: usize) -> bool {
        self.disable_backend_inner(id, true)
    }

    fn disable_backend_inner(&self, id: usize, kill_inflight: bool) -> bool {
        if let Some(b) = self.backends.iter().find(|b| b.id == id) {
            b.admin_disabled.store(true, Ordering::Relaxed);
            b.enabled.store(false, Ordering::Relaxed);
            b.stats.hc_status.store(4, Ordering::Relaxed); // admin_disabled
            if kill_inflight {
                b.kill_active();
            }
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

    /// P1: default admin disable drains — does NOT wake wait_kill.
    #[tokio::test]
    async fn disable_backend_drains_without_killing() {
        let lb = LoadBalancer::new("127.0.0.1:1", LbAlgorithm::RoundRobin).unwrap();
        let backend = lb.backends()[0].clone();

        let b1 = backend.clone();
        let waiter = tokio::spawn(async move { b1.wait_kill().await });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(lb.disable_backend(0));
        assert!(!backend.enabled.load(Ordering::Relaxed));
        assert!(backend.admin_disabled.load(Ordering::Relaxed));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waiter.is_finished(),
            "default admin disable must drain, not kill in-flight"
        );
        // New picks must skip the disabled backend.
        assert!(lb.next_backend().is_none());
        waiter.abort();
    }

    /// Explicit kill path still aborts in-flight relays.
    #[tokio::test]
    async fn disable_backend_kill_wakes_waiters() {
        let lb = LoadBalancer::new("127.0.0.1:1", LbAlgorithm::RoundRobin).unwrap();
        let backend = lb.backends()[0].clone();

        let b1 = backend.clone();
        let waiter = tokio::spawn(async move { b1.wait_kill().await });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(lb.disable_backend_kill(0));

        tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("disable_backend_kill did not propagate kill")
            .unwrap();
    }

    #[tokio::test]
    async fn next_backend_skips_disabled_without_alloc_path() {
        let lb = LoadBalancer::new(
            "127.0.0.1:1,127.0.0.1:2,127.0.0.1:3",
            LbAlgorithm::RoundRobin,
        )
        .unwrap();
        assert!(lb.disable_backend(1));
        // All picks should be id 0 or 2.
        for _ in 0..20 {
            let b = lb.next_backend().unwrap();
            assert_ne!(b.id, 1);
        }
    }

    fn failover_lb() -> LoadBalancer {
        LoadBalancer::new(
            "127.0.0.1:11180,127.0.0.1:11181,127.0.0.1:11190,127.0.0.1:11191",
            LbAlgorithm::Failover,
        )
        .unwrap()
    }

    #[test]
    fn failover_from_str_aliases() {
        for s in ["failover", "priority", "sticky", "prio", "FAILOVER"] {
            assert_eq!(LbAlgorithm::from_str(s).unwrap(), LbAlgorithm::Failover);
        }
        assert_eq!(LbAlgorithm::Failover.as_str(), "failover");
        assert!(LbAlgorithm::from_str("leastconn").is_err());
    }

    #[test]
    fn failover_stays_on_priority_1_while_healthy() {
        let lb = failover_lb();
        for _ in 0..20 {
            assert_eq!(lb.next_backend().unwrap().id, 0);
        }
        assert_eq!(lb.sticky_id(), Some(0));
    }

    #[test]
    fn failover_goes_next_when_current_fails_and_never_fails_back() {
        let lb = failover_lb();
        assert_eq!(lb.next_backend().unwrap().id, 0);

        // p1 down → p2
        assert!(lb.disable_backend(0));
        assert_eq!(lb.next_backend().unwrap().id, 1);
        assert_eq!(lb.sticky_id(), Some(1));

        // p1 recovers: stay on p2 ("if works never switch")
        assert!(lb.enable_backend(0));
        for _ in 0..10 {
            assert_eq!(lb.next_backend().unwrap().id, 1);
        }

        // p2 down → p3, not back to recovered p1 ("go next")
        assert!(lb.disable_backend(1));
        assert_eq!(lb.next_backend().unwrap().id, 2);
        assert!(lb.enable_backend(1));
        assert_eq!(lb.next_backend().unwrap().id, 2);

        // p3 down → p4
        assert!(lb.disable_backend(2));
        assert_eq!(lb.next_backend().unwrap().id, 3);

        // p4 down: wrap, p1 is the first remaining enabled
        assert!(lb.disable_backend(3));
        assert_eq!(lb.next_backend().unwrap().id, 0);
    }

    #[test]
    fn failover_skips_disabled_and_returns_none_when_all_down() {
        let lb = failover_lb();
        assert_eq!(lb.next_backend().unwrap().id, 0);
        assert!(lb.disable_backend(0));
        assert!(lb.disable_backend(2)); // skip p3
        assert_eq!(lb.next_backend().unwrap().id, 1);
        assert!(lb.disable_backend(1));
        assert_eq!(lb.next_backend().unwrap().id, 3);
        assert!(lb.disable_backend(3));
        assert!(lb.next_backend().is_none());
        assert_eq!(lb.sticky_id(), Some(3)); // last known, not cleared
    }
}
