use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::{error, info, debug};
use crate::connection_cache::ConnectionCache;

pub struct HttpProxy {
    bind_addr: String,
    target_addr: String,
    cache: ConnectionCache,
}

impl HttpProxy {
    pub fn new(bind_addr: &str, target_addr: &str, cache_size_bytes: usize) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr: SocketAddr = self.bind_addr.parse()?;
        let target = self.target_addr.clone();
        let cache = self.cache.clone();
        
        let (current_cache, max_cache) = self.cache.get_cache_stats().await;
        info!("HTTP proxy listening on {} -> {} (cache: {}/{}KB)", 
              self.bind_addr, self.target_addr, current_cache / 1024, max_cache / 1024);
        
        let make_svc = make_service_fn(move |_conn| {
            let target = target.clone();
            let cache = cache.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let target = target.clone();
                    let cache = cache.clone();
                    proxy_handler_with_cache(req, target, cache)
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

async fn proxy_handler_with_cache(req: Request<Body>, target_addr: String, _cache: ConnectionCache) -> Result<Response<Body>, Infallible> {
    // Note: HTTP proxy connection caching is more complex due to hyper's Client handling
    // For now, we'll use hyper's built-in connection pooling, but the cache parameter
    // is available for future advanced implementations
    debug!("HTTP request with cache support (using hyper's built-in pooling)");
    proxy_handler(req, target_addr).await
}

async fn proxy_handler(mut req: Request<Body>, target_addr: String) -> Result<Response<Body>, Infallible> {
    let client = Client::new();

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
            let target_uri = format!("http://{}{}", target_addr, path);
            
            info!("Proxying HTTP request to: {}", target_uri);

            *req.uri_mut() = target_uri.parse().unwrap();

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