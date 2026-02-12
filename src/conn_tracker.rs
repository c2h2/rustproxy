use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::Serialize;

/* ------------------------------ Data types ------------------------------ */

pub struct ConnInfo {
    pub client_addr: SocketAddr,
    pub ss_target: String,
    pub backend_addr: String,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub started_at: Instant,
    pub started_epoch: u64,
}

#[derive(Serialize)]
pub struct ActiveConnSnapshot {
    pub id: String,
    pub client_addr: String,
    pub ss_target: String,
    pub backend: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub duration_secs: f64,
    pub started_epoch: u64,
}

/* ------------------------------ Tracker ------------------------------ */

pub struct ConnectionTracker {
    active: DashMap<u64, Arc<ConnInfo>>,
    next_id: AtomicU64,
}

impl ConnectionTracker {
    pub fn new(_max_recent: usize) -> Self {
        Self {
            active: DashMap::new(),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn next_conn_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn add(&self, conn_id: u64, client_addr: SocketAddr, ss_target: String, backend_addr: String) {
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let info = Arc::new(ConnInfo {
            client_addr,
            ss_target,
            backend_addr,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            started_at: Instant::now(),
            started_epoch: now_epoch,
        });
        self.active.insert(conn_id, info);
    }

    pub fn update_bytes(&self, conn_id: u64, tx: u64, rx: u64) {
        if let Some(info) = self.active.get(&conn_id) {
            info.tx_bytes.store(tx, Ordering::Relaxed);
            info.rx_bytes.store(rx, Ordering::Relaxed);
        }
    }

    pub fn remove(&self, conn_id: u64) {
        self.active.remove(&conn_id);
    }

    pub fn snapshot_active(&self) -> Vec<ActiveConnSnapshot> {
        let now = Instant::now();
        self.active
            .iter()
            .map(|entry| {
                let id = *entry.key();
                let info = entry.value();
                ActiveConnSnapshot {
                    id: id.to_string(),
                    client_addr: info.client_addr.to_string(),
                    ss_target: info.ss_target.clone(),
                    backend: info.backend_addr.clone(),
                    tx_bytes: info.tx_bytes.load(Ordering::Relaxed),
                    rx_bytes: info.rx_bytes.load(Ordering::Relaxed),
                    duration_secs: now.duration_since(info.started_at).as_secs_f64(),
                    started_epoch: info.started_epoch,
                }
            })
            .collect()
    }

    #[allow(dead_code)]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}
