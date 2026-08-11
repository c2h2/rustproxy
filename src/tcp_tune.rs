//! Runtime-tunable TCP socket options (keepalive, user timeout, buffer sizes).
//!
//! **Defaults favour long-lived / bulk / mobile paths** (less mid-idle
//! disconnect risk) over the older ultra-aggressive NAT-refresh profile:
//!
//! | setting            | legacy (pre-1.12) | current default |
//! |--------------------|-------------------|-----------------|
//! | keepalive time     | 20s               | **120s**        |
//! | keepalive interval | 10s               | **30s**         |
//! | keepalive retries  | 3                 | 3               |
//! | dead-peer detect   | ~50s              | **~210s**       |
//! | TCP_USER_TIMEOUT   | 60s (Linux)       | **off**         |
//! | SO_SNDBUF/RCVBUF   | OS default        | **4 MiB**       |
//!
//! Operators can still select the aggressive profile via CLI flags.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use once_cell::sync::Lazy;

/// Default: first keepalive probe after this idle period.
pub const DEFAULT_KEEPALIVE_TIME_SECS: u64 = 120;
/// Default: interval between successive probes.
pub const DEFAULT_KEEPALIVE_INTERVAL_SECS: u64 = 30;
/// Default: unanswered probes before giving up.
pub const DEFAULT_KEEPALIVE_RETRIES: u32 = 3;
/// Default Linux TCP_USER_TIMEOUT in seconds; **0 means do not set**.
pub const DEFAULT_USER_TIMEOUT_SECS: u64 = 0;
/// Default socket send/recv buffer when not overridden on the CLI.
pub const DEFAULT_SOCK_BUF: usize = 4 * 1024 * 1024;
/// Default / minimum / maximum userspace pump buffer.
///
/// Pumps are adaptive: each direction starts at `MIN_PUMP_BUFFER` and
/// doubles on filled reads up to the `--buffer-size` ceiling (default
/// `MAX_PUMP_BUFFER`), halving again when idle, with every byte
/// accounted against the global budget.
pub const DEFAULT_PUMP_BUFFER: usize = MAX_PUMP_BUFFER;
pub const MIN_PUMP_BUFFER: usize = 8 * 1024;
pub const MAX_PUMP_BUFFER: usize = 4 * 1024 * 1024;
/// Hard cap on total pump-buffer memory across ALL connections (1 GiB).
/// Once spent, pumps stop growing (and new ones start at the 8 KiB
/// floor), so any number of connections stays within the budget.
pub const DEFAULT_PUMP_BUDGET: usize = 1024 * 1024 * 1024;
/// A pump holding more than this shrinks after an idle period.
pub const IDLE_SHRINK_MIN: usize = 64 * 1024;
/// Idle period after which an oversized pump halves its buffer.
pub const IDLE_SHRINK_AFTER: Duration = Duration::from_secs(10);

/* ---------- Legacy aggressive profile (documented + tested) ---------- */

/// Pre-softening defaults kept so tests can prove the old ~50s dead-peer
/// window that could drop briefly-unreachable peers mid-session.
pub const LEGACY_KEEPALIVE_TIME_SECS: u64 = 20;
pub const LEGACY_KEEPALIVE_INTERVAL_SECS: u64 = 10;
pub const LEGACY_KEEPALIVE_RETRIES: u32 = 3;
pub const LEGACY_USER_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct TcpTuneConfig {
    pub keepalive_time: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_retries: u32,
    /// `None` → do not set TCP_USER_TIMEOUT (Linux).
    pub user_timeout: Option<Duration>,
    pub sndbuf: Option<usize>,
    pub rcvbuf: Option<usize>,
}

impl Default for TcpTuneConfig {
    fn default() -> Self {
        Self {
            keepalive_time: Duration::from_secs(DEFAULT_KEEPALIVE_TIME_SECS),
            keepalive_interval: Duration::from_secs(DEFAULT_KEEPALIVE_INTERVAL_SECS),
            keepalive_retries: DEFAULT_KEEPALIVE_RETRIES,
            user_timeout: if DEFAULT_USER_TIMEOUT_SECS == 0 {
                None
            } else {
                Some(Duration::from_secs(DEFAULT_USER_TIMEOUT_SECS))
            },
            sndbuf: Some(DEFAULT_SOCK_BUF),
            rcvbuf: Some(DEFAULT_SOCK_BUF),
        }
    }
}

impl TcpTuneConfig {
    /// The historical aggressive NAT-friendly profile (~50s dead-peer detect,
    /// 60s user timeout, no explicit socket buffer sizes).
    pub fn legacy_aggressive() -> Self {
        Self {
            keepalive_time: Duration::from_secs(LEGACY_KEEPALIVE_TIME_SECS),
            keepalive_interval: Duration::from_secs(LEGACY_KEEPALIVE_INTERVAL_SECS),
            keepalive_retries: LEGACY_KEEPALIVE_RETRIES,
            user_timeout: Some(Duration::from_secs(LEGACY_USER_TIMEOUT_SECS)),
            sndbuf: None,
            rcvbuf: None,
        }
    }

    /// Upper bound on dead-peer detection: keepidle + keepintvl * keepcnt.
    pub fn dead_peer_detect(&self) -> Duration {
        self.keepalive_time + self.keepalive_interval * self.keepalive_retries
    }
}

static TUNE: OnceLock<TcpTuneConfig> = OnceLock::new();

/// Install process-wide TCP tuning. First call wins; later calls are ignored
/// (returns `false` if already set).
pub fn set_tcp_tune(cfg: TcpTuneConfig) -> bool {
    TUNE.set(cfg).is_ok()
}

/// Active config (defaults if never set).
pub fn tcp_tune() -> &'static TcpTuneConfig {
    static FALLBACK: Lazy<TcpTuneConfig> = Lazy::new(TcpTuneConfig::default);
    TUNE.get().unwrap_or(&FALLBACK)
}

/// Clamp a CLI `--buffer-size` into a sensible per-direction pump buffer.
pub fn clamp_pump_buffer(requested: usize) -> usize {
    if requested == 0 {
        return DEFAULT_PUMP_BUFFER;
    }
    requested.clamp(MIN_PUMP_BUFFER, MAX_PUMP_BUFFER)
}

/* ---------- Global pump-buffer memory budget ---------- */

/// Accounts pump-buffer bytes handed out to live connections against a
/// hard cap, so total relay memory stays bounded no matter how many
/// connections are open.
#[derive(Debug)]
pub struct PumpBudget {
    cap: usize,
    used: AtomicUsize,
}

/// Bytes reserved against a [`PumpBudget`]; returned to the budget on drop.
#[derive(Debug)]
pub struct PumpLease<'a> {
    budget: &'a PumpBudget,
    granted: usize,
}

impl PumpBudget {
    pub const fn new(cap: usize) -> Self {
        Self {
            cap,
            used: AtomicUsize::new(0),
        }
    }

    /// Starter grant of `MIN_PUMP_BUFFER`. Always succeeds — the floor
    /// overshoot past the cap is bounded by the fd-derived connection
    /// cap — so a new connection never fails for lack of budget.
    pub fn reserve_min(&self) -> PumpLease<'_> {
        self.used.fetch_add(MIN_PUMP_BUFFER, Ordering::Relaxed);
        PumpLease {
            budget: self,
            granted: MIN_PUMP_BUFFER,
        }
    }

    /// Strict reservation of `extra` bytes; fails rather than exceed the cap.
    fn try_reserve_extra(&self, extra: usize) -> bool {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(extra) else {
                return false;
            };
            if next > self.cap {
                return false;
            }
            match self.used.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::Relaxed);
    }

    pub fn in_use(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
}

impl PumpLease<'_> {
    /// Bytes currently held by this lease.
    pub fn size(&self) -> usize {
        self.granted
    }

    /// Try to grow to `target` bytes; on `false` (budget spent) the lease
    /// keeps its current size and the pump simply stops growing.
    pub fn try_grow_to(&mut self, target: usize) -> bool {
        if target <= self.granted {
            return true;
        }
        if self.budget.try_reserve_extra(target - self.granted) {
            self.granted = target;
            true
        } else {
            false
        }
    }

    /// Shrink to `target` (floored at `MIN_PUMP_BUFFER`), returning the
    /// freed bytes to the budget.
    pub fn shrink_to(&mut self, target: usize) {
        let target = target.max(MIN_PUMP_BUFFER);
        if target < self.granted {
            self.budget.release(self.granted - target);
            self.granted = target;
        }
    }
}

impl Drop for PumpLease<'_> {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.granted, Ordering::Relaxed);
    }
}

/// Process-wide budget shared by every relay path.
pub fn global_pump_budget() -> &'static PumpBudget {
    static GLOBAL: PumpBudget = PumpBudget::new(DEFAULT_PUMP_BUDGET);
    &GLOBAL
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Current product defaults: soft enough for long idle / bulk / mobile.
    #[test]
    fn defaults_are_soft_for_long_idle_and_bulk() {
        let d = TcpTuneConfig::default();
        assert_eq!(d.keepalive_time, Duration::from_secs(120));
        assert_eq!(d.keepalive_interval, Duration::from_secs(30));
        assert_eq!(d.keepalive_retries, 3);
        assert!(
            d.user_timeout.is_none(),
            "TCP_USER_TIMEOUT must be off by default (was 60s — bulk-transfer risk)"
        );
        assert_eq!(d.sndbuf, Some(4 * 1024 * 1024));
        assert_eq!(d.rcvbuf, Some(4 * 1024 * 1024));
        // 120 + 30*3 = 210s before dead-peer drop
        assert_eq!(d.dead_peer_detect(), Duration::from_secs(210));
        assert!(
            d.dead_peer_detect() > Duration::from_secs(90),
            "default dead-peer window should exceed typical short NAT blips"
        );
    }

    /// Documents the **old** default profile that was a mid-idle disconnect risk.
    /// This is the "was broken" baseline: ~50s dead-peer detect + 60s user timeout.
    #[test]
    fn legacy_aggressive_profile_had_50s_dead_peer_detect() {
        let legacy = TcpTuneConfig::legacy_aggressive();
        assert_eq!(legacy.keepalive_time, Duration::from_secs(20));
        assert_eq!(legacy.keepalive_interval, Duration::from_secs(10));
        assert_eq!(legacy.keepalive_retries, 3);
        assert_eq!(legacy.dead_peer_detect(), Duration::from_secs(50));
        assert_eq!(legacy.user_timeout, Some(Duration::from_secs(60)));
        assert!(legacy.sndbuf.is_none());
        assert!(legacy.rcvbuf.is_none());

        let soft = TcpTuneConfig::default();
        assert!(
            soft.dead_peer_detect() > legacy.dead_peer_detect() * 3,
            "soft default ({:?}) must be much more tolerant than legacy ({:?})",
            soft.dead_peer_detect(),
            legacy.dead_peer_detect()
        );
        assert!(
            soft.user_timeout.is_none() && legacy.user_timeout.is_some(),
            "soft default disables user timeout that legacy always set"
        );
    }

    #[test]
    fn clamp_pump_buffer_bounds() {
        assert_eq!(clamp_pump_buffer(0), DEFAULT_PUMP_BUFFER);
        assert_eq!(clamp_pump_buffer(100), MIN_PUMP_BUFFER);
        assert_eq!(clamp_pump_buffer(64 * 1024), 64 * 1024);
        assert_eq!(clamp_pump_buffer(usize::MAX), MAX_PUMP_BUFFER);
    }

    /// Adaptive starts: even 10k idle connections cost a fraction of the
    /// budget (2 pumps × 8 KiB each).
    #[test]
    fn pump_budget_idle_connections_are_cheap() {
        assert!(10_000 * 2 * MIN_PUMP_BUFFER <= DEFAULT_PUMP_BUDGET / 6);
    }

    /// Leases grow only while the cap has room, shrink back, and return
    /// their bytes on drop.
    #[test]
    fn pump_lease_grows_shrinks_and_releases() {
        let budget = PumpBudget::new(1024 * 1024);

        let mut l1 = budget.reserve_min();
        assert_eq!(l1.size(), MIN_PUMP_BUFFER);
        assert!(l1.try_grow_to(512 * 1024));
        assert_eq!(l1.size(), 512 * 1024);

        // Growing past the cap is refused; the lease keeps its size.
        let mut l2 = budget.reserve_min();
        assert!(!l2.try_grow_to(1024 * 1024));
        assert_eq!(l2.size(), MIN_PUMP_BUFFER);

        // Growing within what is left succeeds.
        assert!(l2.try_grow_to(256 * 1024));
        assert!(budget.in_use() <= 1024 * 1024);

        // Shrinking hands bytes back for others to grow into.
        l1.shrink_to(64 * 1024);
        assert_eq!(l1.size(), 64 * 1024);
        assert!(l2.try_grow_to(512 * 1024));

        drop(l1);
        drop(l2);
        assert_eq!(budget.in_use(), 0);
    }
}
