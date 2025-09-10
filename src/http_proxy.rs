use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};
use crate::connection_cache::ConnectionCache;
use crate::stats::StatsCollector;

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
        
        let make_svc = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
            let target = target.clone();
            let cache = cache.clone();
            let stats = stats.clone();
            let client_addr = conn.remote_addr();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let target = target.clone();
                    let cache = cache.clone();
                    let stats = stats.clone();
                    proxy_handler_with_stats(req, target, cache, stats, client_addr)
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);

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
) -> Result<Response<Body>, Infallible> {
    let client = Client::new();
    
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
            // Handle HTTPS CONNECT method
            let response = Response::builder()
                .status(200)
                .body(Body::from("Connection established"))
                .unwrap();
            
            // Close connection in stats
            if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                stats.close_connection(conn_id).await;
            }
            
            Ok(response)
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
                Ok(resp) => {
                    // Note: For HTTP requests, we can't easily track bytes without intercepting the body
                    // This would require more complex body streaming. For now, we'll track connections only.
                    if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                        // Estimate based on headers size (simplified tracking)
                        stats.update_connection(conn_id, 1024, 1024).await;
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
                        .status(500)
                        .body(Body::from("Proxy error"))
                        .unwrap())
                }
            }
        }
    }
}

#[allow(dead_code)]
async fn proxy_handler(mut req: Request<Body>, _target_addr: String) -> Result<Response<Body>, Infallible> {
    let client = Client::new();
    
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
    use hyper::{Client, Request, Uri};
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

        let client = Client::new();
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

        let uri = Uri::try_from("http://127.0.0.1:8080/api/test").unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::from("test data"))
            .unwrap();

        let response = proxy_handler(req, target).await.unwrap();
        assert_eq!(response.status(), 200);
    }
}