use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rustproxy::lb::{LbAlgorithm, LoadBalancer};
use rustproxy::traffic_log::TrafficLog;
use rustproxy::web::{build_router, WebState};

use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Helper: spin up axum on a random port, return (base_url, state)
// ---------------------------------------------------------------------------

async fn start_test_web_server() -> (String, Arc<WebState>) {
    let lb = Arc::new(
        LoadBalancer::new("127.0.0.1:9001,127.0.0.1:9002", LbAlgorithm::RoundRobin).unwrap(),
    );

    let tmp = std::env::temp_dir().join(format!(
        "rustproxy_test_traffic_{}.csv",
        std::process::id()
    ));
    let traffic_log = Arc::new(TrafficLog::load(&tmp));

    let state = Arc::new(WebState {
        lb: lb.clone(),
        listen_addr: "127.0.0.1:0".to_string(),
        active_connections: Arc::new(AtomicUsize::new(0)),
        total_tx_bytes: Arc::new(AtomicU64::new(0)),
        total_rx_bytes: Arc::new(AtomicU64::new(0)),
        start_time: Instant::now(),
        max_connections: 10000,
        traffic_log,
        conn_tracker: None,
        ss_mode: false,
        ss_method: String::new(),
        ss_listen_port: String::new(),
        vmess_mode: false,
        vmess_listen_port: String::new(),
        cmdline_args: String::new(),
    });

    let app = build_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), state)
}

// ===========================================================================
// LB-level tests (no web server needed)
// ===========================================================================

#[tokio::test]
async fn test_disable_sets_admin_disabled_and_hc_status() {
    let lb = LoadBalancer::new("127.0.0.1:9001,127.0.0.1:9002", LbAlgorithm::RoundRobin).unwrap();

    assert!(lb.disable_backend(0));

    let b = &lb.backends()[0];
    assert!(!b.enabled.load(Ordering::Relaxed));
    assert!(b.admin_disabled.load(Ordering::Relaxed));
    assert_eq!(b.stats.hc_status.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn test_enable_clears_admin_disabled() {
    let lb = LoadBalancer::new("127.0.0.1:9001,127.0.0.1:9002", LbAlgorithm::RoundRobin).unwrap();

    lb.disable_backend(0);
    lb.enable_backend(0);

    let b = &lb.backends()[0];
    assert!(b.enabled.load(Ordering::Relaxed));
    assert!(!b.admin_disabled.load(Ordering::Relaxed));
    assert_eq!(b.stats.hc_status.load(Ordering::Relaxed), 0); // reset to unknown
}

#[tokio::test]
async fn test_admin_disabled_skipped_by_next_backend() {
    let lb = LoadBalancer::new("127.0.0.1:9001,127.0.0.1:9002", LbAlgorithm::RoundRobin).unwrap();

    lb.disable_backend(0);

    // All picks should be backend 1
    for _ in 0..10 {
        let picked = lb.next_backend().unwrap();
        assert_eq!(picked.id, 1);
    }
}

#[tokio::test]
async fn test_snapshot_includes_admin_disabled() {
    let lb = LoadBalancer::new("127.0.0.1:9001,127.0.0.1:9002", LbAlgorithm::RoundRobin).unwrap();

    lb.disable_backend(1);

    let snap = lb.snapshot();
    assert_eq!(snap.len(), 2);

    // Backend 0: untouched
    assert!(snap[0].enabled);
    assert!(!snap[0].admin_disabled);
    assert_eq!(snap[0].hc_status, 0);

    // Backend 1: admin-disabled
    assert!(!snap[1].enabled);
    assert!(snap[1].admin_disabled);
    assert_eq!(snap[1].hc_status, 4);
}

// ===========================================================================
// Web API tests (spin up axum, use reqwest)
// ===========================================================================

#[tokio::test]
async fn test_api_disable_enable_roundtrip() {
    let (base, _state) = start_test_web_server().await;
    let client = reqwest::Client::new();

    // Disable backend 0
    let resp = client
        .post(format!("{}/api/backends/0/disable", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify via /api/stats
    let stats: serde_json::Value = client
        .get(format!("{}/api/stats", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let backends = stats["backends"].as_array().unwrap();
    assert!(backends[0]["admin_disabled"].as_bool().unwrap());
    assert!(!backends[0]["enabled"].as_bool().unwrap());
    assert_eq!(backends[0]["hc_status"].as_u64().unwrap(), 4);

    // Re-enable backend 0
    let resp = client
        .post(format!("{}/api/backends/0/enable", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify cleared
    let stats: serde_json::Value = client
        .get(format!("{}/api/stats", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let backends = stats["backends"].as_array().unwrap();
    assert!(!backends[0]["admin_disabled"].as_bool().unwrap());
    assert!(backends[0]["enabled"].as_bool().unwrap());
    assert_eq!(backends[0]["hc_status"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn test_api_disable_nonexistent_returns_404() {
    let (base, _state) = start_test_web_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/backends/99/disable", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_api_stats_shows_admin_disabled_field() {
    let (base, _state) = start_test_web_server().await;
    let client = reqwest::Client::new();

    let stats: serde_json::Value = client
        .get(format!("{}/api/stats", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let backends = stats["backends"].as_array().unwrap();
    assert_eq!(backends.len(), 2);

    // Every backend must have the admin_disabled field
    for b in backends {
        assert!(
            b.get("admin_disabled").is_some(),
            "backend missing admin_disabled field"
        );
    }
}
