use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::SocketAddr;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
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
    total_stats: Arc<RwLock<(u64, u64, u64)>>, // (total_connections, total_sent, total_received)
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
            total_stats: Arc::new(RwLock::new((0, 0, 0))),
            start_time,
            manager_addr,
        }
    }
    
    pub async fn new_connection(&self, client_addr: SocketAddr, target: String) -> String {
        let conn_id = format!("{}_{}", client_addr, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis());
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
        
        let mut total = self.total_stats.write().await;
        total.0 += 1;
        
        conn_id
    }
    
    pub async fn update_connection(&self, conn_id: &str, bytes_sent: u64, bytes_received: u64) {
        if let Some(mut conn) = self.connections.get_mut(conn_id) {
            conn.bytes_sent += bytes_sent;
            conn.bytes_received += bytes_received;
            conn.last_activity = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            
            let mut total = self.total_stats.write().await;
            total.1 += bytes_sent;
            total.2 += bytes_received;
        }
    }
    
    pub async fn close_connection(&self, conn_id: &str) {
        if let Some(mut conn) = self.connections.get_mut(conn_id) {
            conn.active = false;
            conn.last_activity = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        }
    }
    
    pub async fn get_stats(&self) -> ProxyStats {
        let total = self.total_stats.read().await;
        let connections: Vec<ConnectionStats> = self.connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        let active_connections = connections.iter().filter(|c| c.active).count() as u64;
        
        ProxyStats {
            proxy_id: self.proxy_id.clone(),
            proxy_type: self.proxy_type.clone(),
            listen_addr: self.listen_addr.clone(),
            total_connections: total.0,
            active_connections,
            total_bytes_sent: total.1,
            total_bytes_received: total.2,
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
    
    pub async fn cleanup_inactive(&self, timeout_secs: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let to_remove: Vec<String> = self.connections
            .iter()
            .filter(|entry| !entry.value().active && (now - entry.value().last_activity) > timeout_secs)
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

    /// Characterization: closed connections stay in the map until
    /// `cleanup_inactive` is called. The proxy reporting loop never
    /// calls it, so with `--manager-addr` the map grows without bound
    /// (modulo the conn_id collision bug covered below).
    #[tokio::test]
    async fn closed_connections_accumulate_until_cleanup() {
        let stats = StatsCollector::new("tcp", "127.0.0.1:9", None);

        // Distinct client ports so millis-based ids cannot collide.
        let id1 = stats.new_connection(addr_on_port(10001), "t1".into()).await;
        let id2 = stats.new_connection(addr_on_port(10002), "t2".into()).await;
        assert_ne!(id1, id2);
        stats.close_connection(&id1).await;
        stats.close_connection(&id2).await;

        assert_eq!(stats.connections.len(), 2, "close must not remove entries");

        // cleanup with huge timeout keeps them (not old enough).
        stats.cleanup_inactive(u64::MAX).await;
        assert_eq!(stats.connections.len(), 2);

        // Predicate is `(now - last_activity) > timeout_secs` (strict), so
        // same-second closes are NOT removed by timeout=0. Sleep past the
        // second boundary, then clean.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        stats.cleanup_inactive(0).await;
        assert_eq!(
            stats.connections.len(),
            0,
            "cleanup_inactive(0) must drop inactive entries older than this second"
        );
    }

    /// Active connections are never cleaned even with timeout 0.
    #[tokio::test]
    async fn cleanup_inactive_preserves_active() {
        let stats = StatsCollector::new("tcp", "127.0.0.1:9", None);
        let _id = stats.new_connection(addr_on_port(10003), "live".into()).await;
        stats.cleanup_inactive(0).await;
        assert_eq!(stats.connections.len(), 1);
    }

    /// `conn_id = "{client_addr}_{millis}"` is not unique under concurrent
    /// accepts from the same peer address within the same millisecond.
    /// DashMap insert then overwrites, so the map under-counts and
    /// `total_connections` can disagree with retained rows.
    ///
    /// This is a real stats-correctness / memory-accounting bug on busy
    /// proxies (many short conns from one IP, or same src port reuse).
    #[tokio::test]
    async fn connection_ids_collide_for_same_client_same_millis() {
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
        // If this starts passing with unique==40, the id scheme was fixed.
        assert!(
            unique.len() < ids.len(),
            "expected millis-based conn_id collisions for same peer; got {} unique of {}",
            unique.len(),
            ids.len()
        );
        // Map cannot hold more entries than unique ids.
        assert_eq!(stats.connections.len(), unique.len());
        // total_connections still increments once per call (write-locked).
        let snap = stats.get_stats().await;
        assert_eq!(snap.total_connections, 40);
        assert!(
            snap.connections.len() < 40,
            "colliding inserts must leave fewer retained connection rows than opens"
        );
    }

    /// With distinct peers, concurrent opens all land in the map and the
    /// totals write-lock path still counts correctly.
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