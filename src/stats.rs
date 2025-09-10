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