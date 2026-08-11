use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::SocketAddr;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use tracing::{debug, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub client_ip: String,
    pub target: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub start_time: u64,
    pub last_activity: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStats {
    pub proxy_id: String,
    pub proxy_type: String,
    pub listen_addr: String,
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub connections: Vec<ConnectionStats>,
    pub start_time: u64,
    pub last_report: u64,
}

#[derive(Clone)]
pub struct StatsCollector {
    proxy_id: String,
    proxy_type: String,
    listen_addr: String,
    connections: Arc<DashMap<String, ConnectionStats>>,
    /// Monotonic id counter — avoids `{addr}_{millis}` collisions under concurrent opens.
    next_id: Arc<AtomicU64>,
    total_connections: Arc<AtomicU64>,
    total_bytes_sent: Arc<AtomicU64>,
    total_bytes_received: Arc<AtomicU64>,
    start_time: u64,
    manager_addr: Option<SocketAddr>,
}

impl StatsCollector {
    pub fn new(proxy_type: &str, listen_addr: &str, manager_addr: Option<SocketAddr>) -> Self {
        let proxy_id = format!("{}_{}", proxy_type, listen_addr.replace(":", "_"));
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        StatsCollector {
            proxy_id,
            proxy_type: proxy_type.to_string(),
            listen_addr: listen_addr.to_string(),
            connections: Arc::new(DashMap::new()),
            next_id: Arc::new(AtomicU64::new(1)),
            total_connections: Arc::new(AtomicU64::new(0)),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
            start_time,
            manager_addr,
        }
    }
    
    pub async fn new_connection(&self, client_addr: SocketAddr, target: String) -> String {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let conn_id = format!("{}_{}", client_addr, id);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let stats = ConnectionStats {
            client_ip: client_addr.to_string(),
            target,
            bytes_sent: 0,
            bytes_received: 0,
            start_time: now,
            last_activity: now,
            active: true,
        };
        
        self.connections.insert(conn_id.clone(), stats);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        
        conn_id
    }
    
    pub async fn update_connection(&self, conn_id: &str, bytes_sent: u64, bytes_received: u64) {
        if let Some(mut conn) = self.connections.get_mut(conn_id) {
            conn.bytes_sent += bytes_sent;
            conn.bytes_received += bytes_received;
            conn.last_activity = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            
            self.total_bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
            self.total_bytes_received.fetch_add(bytes_received, Ordering::Relaxed);
        }
    }
    
    pub async fn close_connection(&self, conn_id: &str) {
        if let Some(mut conn) = self.connections.get_mut(conn_id) {
            conn.active = false;
            conn.last_activity = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        }
    }
    
    pub async fn get_stats(&self) -> ProxyStats {
        let connections: Vec<ConnectionStats> = self.connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        let active_connections = connections.iter().filter(|c| c.active).count() as u64;
        
        ProxyStats {
            proxy_id: self.proxy_id.clone(),
            proxy_type: self.proxy_type.clone(),
            listen_addr: self.listen_addr.clone(),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections,
            total_bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
            total_bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
            connections,
            start_time: self.start_time,
            last_report: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        }
    }
    
    pub async fn start_reporting(self: Arc<Self>) {
        if let Some(manager_addr) = self.manager_addr {
            tokio::spawn(async move {
                let socket = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        error!("Failed to create UDP socket for stats reporting: {}", e);
                        return;
                    }
                };
                
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                
                loop {
                    interval.tick().await;

                    // Drop closed connections older than 60s so the map cannot
                    // grow without bound under high churn.
                    self.cleanup_inactive(60).await;
                    
                    let stats = self.get_stats().await;
                    let json = match serde_json::to_string(&stats) {
                        Ok(j) => j,
                        Err(e) => {
                            error!("Failed to serialize stats: {}", e);
                            continue;
                        }
                    };
                    
                    if let Err(e) = socket.send_to(json.as_bytes(), manager_addr).await {
                        debug!("Failed to send stats to manager: {}", e);
                    }
                }
            });
        }
    }
    
    /// Remove inactive connections whose last_activity is at least
    /// `timeout_secs` in the past (`>=`, so timeout 0 clears all inactive).
    pub async fn cleanup_inactive(&self, timeout_secs: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let to_remove: Vec<String> = self.connections
            .iter()
            .filter(|entry| {
                !entry.value().active
                    && now.saturating_sub(entry.value().last_activity) >= timeout_secs
            })
            .map(|entry| entry.key().clone())
            .collect();
        
        for key in to_remove {
            self.connections.remove(&key);
        }
    }
}

pub fn get_manager_addr() -> Option<SocketAddr> {
    std::env::var("RUSTPROXY_MANAGER")
        .ok()
        .and_then(|addr| addr.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr_on_port(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn closed_connections_accumulate_until_cleanup() {
        let stats = StatsCollector::new("tcp", "127.0.0.1:9", None);

        let id1 = stats.new_connection(addr_on_port(10001), "t1".into()).await;
        let id2 = stats.new_connection(addr_on_port(10002), "t2".into()).await;
        assert_ne!(id1, id2);
        stats.close_connection(&id1).await;
        stats.close_connection(&id2).await;

        assert_eq!(stats.connections.len(), 2, "close must not remove entries");

        stats.cleanup_inactive(u64::MAX).await;
        assert_eq!(stats.connections.len(), 2);

        // timeout_secs=0 with `>=` removes all inactive immediately.
        stats.cleanup_inactive(0).await;
        assert_eq!(
            stats.connections.len(),
            0,
            "cleanup_inactive(0) must drop all inactive entries"
        );
    }

    #[tokio::test]
    async fn cleanup_inactive_preserves_active() {
        let stats = StatsCollector::new("tcp", "127.0.0.1:9", None);
        let _id = stats.new_connection(addr_on_port(10003), "live".into()).await;
        stats.cleanup_inactive(0).await;
        assert_eq!(stats.connections.len(), 1);
    }

    /// P0 fix: concurrent opens from the same peer must retain unique rows.
    #[tokio::test]
    async fn concurrent_same_peer_all_ids_unique() {
        let stats = Arc::new(StatsCollector::new("tcp", "127.0.0.1:9", None));
        let peer = addr_on_port(44321);
        let mut handles = Vec::new();
        for i in 0..40 {
            let s = stats.clone();
            handles.push(tokio::spawn(async move {
                s.new_connection(peer, format!("t{i}")).await
            }));
        }
        let mut ids = Vec::new();
        for h in handles {
            ids.push(h.await.unwrap());
        }
        let unique: std::collections::HashSet<_> = ids.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "conn_ids must be unique under concurrent same-peer opens"
        );
        assert_eq!(stats.connections.len(), 40);
        let snap = stats.get_stats().await;
        assert_eq!(snap.total_connections, 40);
    }

    #[tokio::test]
    async fn concurrent_new_connection_unique_peers_all_retained() {
        let stats = Arc::new(StatsCollector::new("tcp", "127.0.0.1:9", None));
        let mut handles = Vec::new();
        for i in 0..50u16 {
            let s = stats.clone();
            handles.push(tokio::spawn(async move {
                s.new_connection(addr_on_port(20000 + i), format!("t{i}")).await
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let snap = stats.get_stats().await;
        assert_eq!(snap.total_connections, 50);
        assert_eq!(snap.connections.len(), 50);
    }
}
