use hyper::client::HttpConnector;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};
use crate::connection_cache::ConnectionCache;
use crate::dns::{self, HyperResolver};
use crate::stats::StatsCollector;

fn build_client() -> Client<HttpConnector<HyperResolver>> {
    let mut connector = HttpConnector::new_with_resolver(HyperResolver);
    connector.enforce_http(false);
    connector.set_nodelay(true);
    // Keep idle backend connections around so repeat requests to the same
    // host reuse the TCP connection instead of re-dialing (Squid-style
    // persistent backend pool).
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(128)
        .build(connector)
}

pub struct HttpProxy {
    bind_addr: String,
    target_addr: String,
    cache: ConnectionCache,
    stats: Option<Arc<StatsCollector>>,
}

impl HttpProxy {
    #[allow(dead_code)]
    pub fn new(bind_addr: &str, target_addr: &str, cache_size_bytes: usize) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            stats: None,
        }
    }
    
    pub fn with_stats(bind_addr: &str, target_addr: &str, cache_size_bytes: usize, manager_addr: Option<SocketAddr>) -> Self {
        let stats = manager_addr.map(|addr| {
            Arc::new(StatsCollector::new("http", bind_addr, Some(addr)))
        });
        
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            stats,
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr: SocketAddr = self.bind_addr.parse()?;
        let target = self.target_addr.clone();
        let cache = self.cache.clone();
        let stats = self.stats.clone();
        
        let (current_cache, max_cache) = self.cache.get_cache_stats().await;
        info!("HTTP proxy listening on {} -> {} (cache: {}/{}KB)", 
              self.bind_addr, self.target_addr, current_cache / 1024, max_cache / 1024);
        
        // Start stats reporting if enabled
        if let Some(ref stats) = self.stats {
            stats.clone().start_reporting().await;
        }
        
        // One shared client: hyper's Client is cheap to clone and all clones
        // share the same backend connection pool.
        let client = build_client();

        let make_svc = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
            let target = target.clone();
            let cache = cache.clone();
            let stats = stats.clone();
            let client = client.clone();
            let client_addr = conn.remote_addr();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let target = target.clone();
                    let cache = cache.clone();
                    let stats = stats.clone();
                    let client = client.clone();
                    proxy_handler_with_stats(req, target, cache, stats, client_addr, client)
                }))
            }
        });

        // NODELAY on accepted client sockets: without it, Nagle batches the
        // small TLS records flowing through CONNECT tunnels and adds latency.
        let server = Server::bind(&addr).tcp_nodelay(true).serve(make_svc);

        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
        }

        Ok(())
    }
}


async fn proxy_handler_with_stats(
    mut req: Request<Body>,
    _target_addr: String,
    _cache: ConnectionCache,
    stats: Option<Arc<StatsCollector>>,
    client_addr: SocketAddr,
    client: Client<HttpConnector<HyperResolver>>,
) -> Result<Response<Body>, Infallible> {
    // Extract target host from the request
    let target_host = if let Some(host) = req.headers().get("host") {
        host.to_str().unwrap_or("").to_string()
    } else if let Some(authority) = req.uri().authority() {
        authority.to_string()
    } else {
        error!("No host header or authority in request");
        return Ok(Response::builder()
            .status(400)
            .body(Body::from("Bad Request: No host specified"))
            .unwrap());
    };
    
    // Extract target for stats
    let target_for_stats = if req.method() == Method::CONNECT {
        req.uri().to_string()
    } else {
        let path = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
        format!("http://{}{}", target_host, path)
    };
    
    // Create stats connection ID if stats are enabled
    let conn_id = if let Some(ref stats) = stats {
        Some(stats.new_connection(client_addr, target_for_stats.clone()).await)
    } else {
        None
    };

    match req.method() {
        &Method::CONNECT => {
            // HTTPS CONNECT tunnel: parse host:port, accept the upgrade, and
            // bidirectionally copy bytes between client and target.
            let authority = match req.uri().authority() {
                Some(a) => a.to_string(),
                None => target_host.clone(),
            };
            if !authority.contains(':') {
                error!("CONNECT request missing port: {}", authority);
                if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                    stats.close_connection(conn_id).await;
                }
                return Ok(Response::builder()
                    .status(400)
                    .body(Body::from("Bad Request: CONNECT requires host:port"))
                    .unwrap());
            }

            let stats_clone = stats.clone();
            let conn_id_clone = conn_id.clone();
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        match dns::tcp_connect(&authority).await {
                            Ok(mut server) => {
                                // Idle HTTPS tunnels (long-lived TLS sessions)
                                // die on NAT/firewall timeout without keepalive.
                                crate::tcp_proxy::tune_tcp_stream(&server);
                                let mut upgraded = upgraded;
                                match tokio::io::copy_bidirectional(&mut upgraded, &mut server).await {
                                    Ok((from_client, from_server)) => {
                                        if let (Some(stats), Some(conn_id)) = (&stats_clone, &conn_id_clone) {
                                            stats.update_connection(conn_id, from_client, from_server).await;
                                        }
                                    }
                                    Err(e) => error!("CONNECT tunnel error for {}: {}", authority, e),
                                }
                            }
                            Err(e) => error!("Failed to connect to {}: {}", authority, e),
                        }
                    }
                    Err(e) => error!("Upgrade error: {}", e),
                }
                if let (Some(stats), Some(conn_id)) = (&stats_clone, &conn_id_clone) {
                    stats.close_connection(conn_id).await;
                }
            });

            Ok(Response::builder()
                .status(200)
                .body(Body::empty())
                .unwrap())
        }
        _ => {
            // Handle regular HTTP requests by forwarding to target
            let path = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
            let target_uri = format!("http://{}{}", target_host, path);

            debug!("Proxying HTTP request to: {}", target_uri);

            *req.uri_mut() = match target_uri.parse() {
                Ok(uri) => uri,
                Err(e) => {
                    error!("Failed to parse target URI {}: {}", target_uri, e);
                    return Ok(Response::builder()
                        .status(400)
                        .body(Body::from("Bad Request: Invalid target URI"))
                        .unwrap());
                }
            };

            // Strip hop-by-hop headers so a client's `Connection: close` (or
            // `Proxy-Connection`) doesn't tear down pooled backend connections.
            for h in ["proxy-connection", "connection", "keep-alive"] {
                req.headers_mut().remove(h);
            }

            // Only buffer bodies when stats need byte counts; otherwise
            // stream straight through.
            if stats.is_none() {
                return match client.request(req).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => {
                        error!("Error proxying request: {}", e);
                        Ok(Response::builder()
                            .status(502)
                            .body(Body::from("Proxy error"))
                            .unwrap())
                    }
                };
            }

            // Extract and measure request body
            let (parts, body) = req.into_parts();
            let body_bytes = hyper::body::to_bytes(body).await.unwrap_or_default();
            let request_size = body_bytes.len() as u64;
            let req = Request::from_parts(parts, Body::from(body_bytes));

            match client.request(req).await {
                Ok(resp) => {
                    // Extract and measure response body
                    let (parts, body) = resp.into_parts();
                    let body_bytes = hyper::body::to_bytes(body).await.unwrap_or_default();
                    let response_size = body_bytes.len() as u64;
                    let resp = Response::from_parts(parts, Body::from(body_bytes));

                    // Update stats with actual bytes transferred
                    if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                        stats.update_connection(conn_id, request_size, response_size).await;
                        stats.close_connection(conn_id).await;
                    }
                    Ok(resp)
                }
                Err(e) => {
                    error!("Error proxying request: {}", e);

                    // Close connection in stats
                    if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                        stats.close_connection(conn_id).await;
                    }

                    Ok(Response::builder()
                        .status(502)
                        .body(Body::from("Proxy error"))
                        .unwrap())
                }
            }
        }
    }
}

#[allow(dead_code)]
async fn proxy_handler(mut req: Request<Body>, _target_addr: String) -> Result<Response<Body>, Infallible> {
    let client = build_client();
    
    // Extract target host from the request
    let target_host = if let Some(host) = req.headers().get("host") {
        host.to_str().unwrap_or("").to_string()
    } else if let Some(authority) = req.uri().authority() {
        authority.to_string()
    } else {
        error!("No host header or authority in request");
        return Ok(Response::builder()
            .status(400)
            .body(Body::from("Bad Request: No host specified"))
            .unwrap());
    };

    match req.method() {
        &Method::CONNECT => {
            // Handle HTTPS CONNECT method
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Connection established"))
                .unwrap())
        }
        _ => {
            // Handle regular HTTP requests by forwarding to target
            let path = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
            let target_uri = format!("http://{}{}", target_host, path);
            
            info!("Proxying HTTP request to: {}", target_uri);

            *req.uri_mut() = match target_uri.parse() {
                Ok(uri) => uri,
                Err(e) => {
                    error!("Failed to parse target URI {}: {}", target_uri, e);
                    return Ok(Response::builder()
                        .status(400)
                        .body(Body::from("Bad Request: Invalid target URI"))
                        .unwrap());
                }
            };

            match client.request(req).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    error!("Error proxying request: {}", e);
                    Ok(Response::builder()
                        .status(500)
                        .body(Body::from("Proxy error"))
                        .unwrap())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockTcpServer;
    use hyper::{Request, Uri};
    use std::convert::TryFrom;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_http_proxy_get_request() {
        tracing_subscriber::fmt::try_init().ok();

        let mock_http_server = MockTcpServer::new().await.unwrap();
        let mock_addr = mock_http_server.addr();
        
        tokio::spawn(mock_http_server.http_server());

        let _proxy = HttpProxy::new("127.0.0.1:0", &format!("127.0.0.1:{}", mock_addr.port()), 128 * 1024);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let target = format!("127.0.0.1:{}", mock_addr.port());
        let make_svc = make_service_fn(move |_conn| {
            let target = target.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let target = target.clone();
                    proxy_handler(req, target)
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);
        let _proxy_addr = server.local_addr();
        
        tokio::spawn(async move {
            let _ = server.await;
        });

        sleep(Duration::from_millis(100)).await;

        let client = build_client();
        let uri = Uri::try_from(format!("http://127.0.0.1:{}/test", mock_addr.port())).unwrap();
        let req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let response = client.request(req).await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_http_proxy_connect_method() {
        tracing_subscriber::fmt::try_init().ok();

        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .body(Body::empty())
            .unwrap();

        let response = proxy_handler(req, "example.com:443".to_string()).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_http_proxy_invalid_request() {
        tracing_subscriber::fmt::try_init().ok();

        let req = Request::builder()
            .uri("http://invalid-host-that-does-not-exist:99999/")
            .body(Body::empty())
            .unwrap();

        let response = proxy_handler(req, "example.com:443".to_string()).await.unwrap();
        assert_eq!(response.status(), 500);
    }

    #[tokio::test]
    async fn test_http_proxy_post_request() {
        tracing_subscriber::fmt::try_init().ok();

        let mock_http_server = MockTcpServer::new().await.unwrap();
        let mock_addr = mock_http_server.addr();
        let target = format!("127.0.0.1:{}", mock_addr.port());
        
        tokio::spawn(mock_http_server.http_server());

        sleep(Duration::from_millis(100)).await;

        let uri = Uri::try_from(format!("http://127.0.0.1:{}/api/test", mock_addr.port())).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::from("test data"))
            .unwrap();

        let response = proxy_handler(req, target).await.unwrap();
        assert_eq!(response.status(), 200);
    }
}