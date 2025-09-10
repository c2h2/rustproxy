use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::SocketAddr;
use dashmap::DashMap;
use axum::{
    extract::{ws::WebSocketUpgrade, State, Query},
    response::{Html, IntoResponse, Json},
    routing::get,
    Router,
};
use axum::extract::ws::{WebSocket, Message};
use futures_util::{SinkExt, StreamExt};
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tracing::{info, error, debug};

use crate::stats::ProxyStats;

#[derive(Clone)]
pub struct ManagerState {
    proxies: Arc<DashMap<String, ProxyStats>>,
    broadcast: broadcast::Sender<String>,
    start_time: u64,
}

#[derive(Serialize)]
struct ManagerStats {
    manager_uptime: u64,
    total_proxies: usize,
    active_proxies: usize,
    total_connections: u64,
    active_connections: u64,
    total_bytes_sent: u64,
    total_bytes_received: u64,
    proxies: Vec<ProxyStats>,
}

#[derive(Deserialize)]
struct FilterParams {
    proxy_id: Option<String>,
    active_only: Option<bool>,
}

pub struct Manager {
    listen_addr: String,
}

impl Manager {
    pub fn new(listen_addr: &str) -> Self {
        Manager {
            listen_addr: listen_addr.to_string(),
        }
    }
    
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let addr: SocketAddr = self.listen_addr.parse()?;
        
        let (tx, _) = broadcast::channel(100);
        
        let state = ManagerState {
            proxies: Arc::new(DashMap::new()),
            broadcast: tx.clone(),
            start_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // Start UDP listener for stats collection
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_listener(addr, state_clone).await {
                error!("UDP listener error: {}", e);
            }
        });
        
        // Start cleanup task
        let state_clone = state.clone();
        tokio::spawn(async move {
            cleanup_task(state_clone).await;
        });
        
        // Build HTTP router
        let app = Router::new()
            .route("/", get(serve_dashboard))
            .route("/api/stats", get(get_stats))
            .route("/api/proxy/:id", get(get_proxy_details))
            .route("/api/proxies", get(list_proxies))
            .route("/ws", get(websocket_handler))
            .route("/api/health", get(health_check))
            .layer(CorsLayer::permissive())
            .with_state(state);
        
        info!("Manager HTTP server listening on {}", addr);
        
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
}

async fn udp_listener(addr: SocketAddr, state: ManagerState) -> Result<(), Box<dyn std::error::Error>> {
    let udp_addr = SocketAddr::new(addr.ip(), addr.port() + 1000);
    let socket = UdpSocket::bind(udp_addr).await?;
    info!("Manager UDP listener on {}", udp_addr);
    
    let mut buf = vec![0u8; 65536];
    
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _addr)) => {
                if let Ok(json_str) = std::str::from_utf8(&buf[..len]) {
                    if let Ok(stats) = serde_json::from_str::<ProxyStats>(json_str) {
                        let proxy_id = stats.proxy_id.clone();
                        state.proxies.insert(proxy_id.clone(), stats.clone());
                        
                        // Broadcast update to WebSocket clients
                        if let Ok(update_json) = serde_json::to_string(&stats) {
                            let _ = state.broadcast.send(update_json);
                        }
                        
                        debug!("Received stats from proxy: {}", proxy_id);
                    }
                }
            }
            Err(e) => {
                error!("UDP receive error: {}", e);
            }
        }
    }
}

async fn cleanup_task(state: ManagerState) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let timeout = 30; // Remove proxies that haven't reported in 30 seconds
        
        let to_remove: Vec<String> = state.proxies
            .iter()
            .filter(|entry| (now - entry.value().last_report) > timeout)
            .map(|entry| entry.key().clone())
            .collect();
        
        for key in to_remove {
            info!("Removing inactive proxy: {}", key);
            state.proxies.remove(&key);
        }
    }
}

async fn serve_dashboard() -> Html<&'static str> {
    Html(include_str!("../static/dashboard.html"))
}

async fn get_stats(State(state): State<ManagerState>) -> Json<ManagerStats> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    let proxies: Vec<ProxyStats> = state.proxies
        .iter()
        .map(|entry| entry.value().clone())
        .collect();
    
    let total_connections: u64 = proxies.iter().map(|p| p.total_connections).sum();
    let active_connections: u64 = proxies.iter().map(|p| p.active_connections).sum();
    let total_bytes_sent: u64 = proxies.iter().map(|p| p.total_bytes_sent).sum();
    let total_bytes_received: u64 = proxies.iter().map(|p| p.total_bytes_received).sum();
    
    let active_proxies = proxies.iter()
        .filter(|p| (now - p.last_report) <= 10)
        .count();
    
    Json(ManagerStats {
        manager_uptime: now - state.start_time,
        total_proxies: proxies.len(),
        active_proxies,
        total_connections,
        active_connections,
        total_bytes_sent,
        total_bytes_received,
        proxies,
    })
}

async fn get_proxy_details(
    axum::extract::Path(id): axum::extract::Path<String>,
    State(state): State<ManagerState>
) -> impl IntoResponse {
    if let Some(proxy) = state.proxies.get(&id) {
        Json(proxy.clone()).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, "Proxy not found").into_response()
    }
}

async fn list_proxies(
    Query(params): Query<FilterParams>,
    State(state): State<ManagerState>
) -> Json<Vec<ProxyStats>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    let mut proxies: Vec<ProxyStats> = state.proxies
        .iter()
        .map(|entry| entry.value().clone())
        .collect();
    
    if let Some(true) = params.active_only {
        proxies.retain(|p| (now - p.last_report) <= 10);
    }
    
    if let Some(proxy_id) = params.proxy_id {
        proxies.retain(|p| p.proxy_id.contains(&proxy_id));
    }
    
    Json(proxies)
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<ManagerState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: ManagerState) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.broadcast.subscribe();
    
    // Send initial stats
    let stats = get_stats(State(state.clone())).await;
    if let Ok(json) = serde_json::to_string(&stats.0) {
        let _ = sender.send(Message::Text(json)).await;
    }
    
    // Spawn task to forward broadcast messages to WebSocket
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });
    
    // Handle incoming messages (if needed)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Close(_) = msg {
                break;
            }
        }
    });
    
    // Wait for either task to finish
    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }))
}