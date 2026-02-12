use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::conn_tracker::ConnectionTracker;
use crate::lb::LoadBalancer;
use crate::traffic_log::TrafficLog;

/* ------------------------------ State ------------------------------ */

pub struct WebState {
    pub lb: Arc<LoadBalancer>,
    pub listen_addr: String,
    pub active_connections: Arc<AtomicUsize>,
    pub total_tx_bytes: Arc<AtomicU64>,
    pub total_rx_bytes: Arc<AtomicU64>,
    pub start_time: Instant,
    pub max_connections: usize,
    pub traffic_log: Arc<TrafficLog>,
    pub conn_tracker: Option<Arc<ConnectionTracker>>,
    pub ss_mode: bool,
    pub ss_method: String,
    pub ss_listen_port: String,
}

/* ------------------------------ JSON types ------------------------------ */

#[derive(Serialize)]
struct BackendsResponse {
    algorithm: String,
    backends: Vec<crate::lb::BackendSnapshot>,
}

#[derive(Serialize)]
struct StatsResponse {
    listen_addr: String,
    algorithm: String,
    uptime_secs: u64,
    active_connections: usize,
    max_connections: usize,
    total_tx_bytes: u64,
    total_rx_bytes: u64,
    backends: Vec<crate::lb::BackendSnapshot>,
    ss_mode: bool,
    ss_method: String,
    ss_listen_port: String,
}

#[derive(Serialize)]
struct ActionResponse {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct TrafficHistoryResponse {
    points: Vec<crate::traffic_log::TrafficSample>,
    total_tx_24h: u64,
    total_rx_24h: u64,
}

#[derive(Serialize)]
struct TrafficDatesResponse {
    dates: Vec<String>,
}

/* ------------------------------ Handlers ------------------------------ */

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/lb_dashboard.html"))
}

async fn api_backends(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    Json(BackendsResponse {
        algorithm: state.lb.algorithm().as_str().to_string(),
        backends: state.lb.snapshot(),
    })
}

async fn api_stats(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let uptime = Instant::now().duration_since(state.start_time).as_secs();
    let tl = &state.traffic_log;
    Json(StatsResponse {
        listen_addr: state.listen_addr.clone(),
        algorithm: state.lb.algorithm().as_str().to_string(),
        uptime_secs: uptime,
        active_connections: state.active_connections.load(Ordering::Relaxed),
        max_connections: state.max_connections,
        total_tx_bytes: tl.adjusted_tx(state.total_tx_bytes.load(Ordering::Relaxed)),
        total_rx_bytes: tl.adjusted_rx(state.total_rx_bytes.load(Ordering::Relaxed)),
        backends: state.lb.snapshot(),
        ss_mode: state.ss_mode,
        ss_method: state.ss_method.clone(),
        ss_listen_port: state.ss_listen_port.clone(),
    })
}

async fn api_health(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let uptime = Instant::now().duration_since(state.start_time).as_secs();
    Json(HealthResponse {
        status: "ok".to_string(),
        uptime_secs: uptime,
    })
}

async fn api_enable_backend(
    State(state): State<Arc<WebState>>,
    Path(id): Path<usize>,
) -> impl IntoResponse {
    if state.lb.enable_backend(id) {
        (
            StatusCode::OK,
            Json(ActionResponse {
                ok: true,
                message: format!("Backend {} enabled", id),
            }),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ActionResponse {
                ok: false,
                message: format!("Backend {} not found", id),
            }),
        )
    }
}

async fn api_disable_backend(
    State(state): State<Arc<WebState>>,
    Path(id): Path<usize>,
) -> impl IntoResponse {
    if state.lb.disable_backend(id) {
        (
            StatusCode::OK,
            Json(ActionResponse {
                ok: true,
                message: format!("Backend {} disabled", id),
            }),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ActionResponse {
                ok: false,
                message: format!("Backend {} not found", id),
            }),
        )
    }
}

async fn api_traffic_history(
    State(state): State<Arc<WebState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    let start = params
        .get("start")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(now - 86400);
    let end = params
        .get("end")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(now);

    let mut points = state.traffic_log.query_range(start, end).await;

    // Downsample if too many points (keep max ~500)
    if points.len() > 500 {
        let step = points.len() / 500;
        points = points.into_iter().step_by(step).collect();
    }

    // Compute 24h totals from deltas
    let samples_24h = state.traffic_log.query_last(86400).await;
    let (total_tx_24h, total_rx_24h) = if samples_24h.len() >= 2 {
        let first = &samples_24h[0];
        let last = &samples_24h[samples_24h.len() - 1];
        (
            last.tx_bytes.saturating_sub(first.tx_bytes),
            last.rx_bytes.saturating_sub(first.rx_bytes),
        )
    } else {
        (0, 0)
    };

    Json(TrafficHistoryResponse {
        points,
        total_tx_24h,
        total_rx_24h,
    })
}

async fn api_traffic_dates(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let dates = state.traffic_log.dates_with_data().await;
    Json(TrafficDatesResponse { dates })
}

#[derive(Serialize)]
struct ConnectionsResponse {
    active: Vec<crate::conn_tracker::ActiveConnSnapshot>,
    recent: Vec<crate::conn_tracker::ClosedConnInfo>,
}

async fn api_connections(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    if let Some(ref tracker) = state.conn_tracker {
        let mut active = tracker.snapshot_active();
        active.sort_by(|a, b| b.duration_secs.partial_cmp(&a.duration_secs).unwrap_or(std::cmp::Ordering::Equal));
        let mut recent = tracker.snapshot_recent().await;
        recent.sort_by(|a, b| b.closed_epoch.cmp(&a.closed_epoch));
        Json(ConnectionsResponse { active, recent })
    } else {
        Json(ConnectionsResponse {
            active: vec![],
            recent: vec![],
        })
    }
}

/* ------------------------------ Server ------------------------------ */

pub async fn start_web_interface(bind_addr: String, state: Arc<WebState>) {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/backends", get(api_backends))
        .route("/api/backends/:id/enable", post(api_enable_backend))
        .route("/api/backends/:id/disable", post(api_disable_backend))
        .route("/api/stats", get(api_stats))
        .route("/api/connections", get(api_connections))
        .route("/api/health", get(api_health))
        .route("/api/traffic/history", get(api_traffic_history))
        .route("/api/traffic/dates", get(api_traffic_dates))
        .with_state(state);

    info!("LB dashboard listening on http://{}", bind_addr);

    match TcpListener::bind(&bind_addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Web interface error: {}", e);
            }
        }
        Err(e) => {
            error!("Failed to bind web interface on {}: {}", bind_addr, e);
        }
    }
}
