use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::lb::LoadBalancer;

/* ------------------------------ State ------------------------------ */

pub struct WebState {
    pub lb: Arc<LoadBalancer>,
    pub listen_addr: String,
    pub active_connections: Arc<AtomicUsize>,
    pub total_tx_bytes: Arc<AtomicU64>,
    pub total_rx_bytes: Arc<AtomicU64>,
    pub start_time: Instant,
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
    total_tx_bytes: u64,
    total_rx_bytes: u64,
    backends: Vec<crate::lb::BackendSnapshot>,
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
    Json(StatsResponse {
        listen_addr: state.listen_addr.clone(),
        algorithm: state.lb.algorithm().as_str().to_string(),
        uptime_secs: uptime,
        active_connections: state.active_connections.load(Ordering::Relaxed),
        total_tx_bytes: state.total_tx_bytes.load(Ordering::Relaxed),
        total_rx_bytes: state.total_rx_bytes.load(Ordering::Relaxed),
        backends: state.lb.snapshot(),
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

/* ------------------------------ Server ------------------------------ */

pub async fn start_web_interface(bind_addr: String, state: Arc<WebState>) {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/backends", get(api_backends))
        .route("/api/backends/:id/enable", post(api_enable_backend))
        .route("/api/backends/:id/disable", post(api_disable_backend))
        .route("/api/stats", get(api_stats))
        .route("/api/health", get(api_health))
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
