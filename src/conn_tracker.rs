use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;

/* ------------------------------ Data types ------------------------------ */

pub struct ConnInfo {
    pub client_addr: SocketAddr,
    pub ss_target: String,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

#[derive(Serialize)]
pub struct SsClientSnapshot {
    pub ip: String,
    pub connections: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
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

    pub fn add(&self, conn_id: u64, client_addr: SocketAddr, ss_target: String) {
        let info = Arc::new(ConnInfo {
            client_addr,
            ss_target,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
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

    /// Return active SS clients grouped by IP, sorted by connection count descending.
    pub fn snapshot_ss_clients(&self) -> Vec<SsClientSnapshot> {
        let mut map: HashMap<IpAddr, (usize, u64, u64)> = HashMap::new();
        for entry in self.active.iter() {
            let info = entry.value();
            // Only SS connections (ss_target is non-empty)
            if info.ss_target.is_empty() {
                continue;
            }
            let ip = info.client_addr.ip();
            let e = map.entry(ip).or_insert((0, 0, 0));
            e.0 += 1;
            e.1 += info.tx_bytes.load(Ordering::Relaxed);
            e.2 += info.rx_bytes.load(Ordering::Relaxed);
        }
        let mut result: Vec<SsClientSnapshot> = map
            .into_iter()
            .map(|(ip, (count, tx, rx))| SsClientSnapshot {
                ip: ip.to_string(),
                connections: count,
                tx_bytes: tx,
                rx_bytes: rx,
            })
            .collect();
        result.sort_by(|a, b| b.connections.cmp(&a.connections));
        result
    }

    #[allow(dead_code)]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}
