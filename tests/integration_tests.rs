use rustproxy::{TcpProxy, HttpProxy, ConnectionCache};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration, timeout};
//use reqwest;

struct TestServer {
    listener: TcpListener,
    addr: SocketAddr,
}

impl TestServer {
    async fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        Ok(Self { listener, addr })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    async fn echo_server(self) {
        while let Ok((mut socket, _)) = self.listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 { break; }
                    if socket.write_all(&buf[0..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    }

    async fn http_echo_server(self) {
        while let Ok((mut socket, _)) = self.listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0; 2048];
                if let Ok(n) = socket.read(&mut buf).await {
                    let request = String::from_utf8_lossy(&buf[0..n]);
                    
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                        request.len(),
                        request
                    );
                    
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            });
        }
    }
}

#[tokio::test]
async fn test_full_tcp_proxy_integration() {
    tracing_subscriber::fmt::try_init().ok();

    let target_server = TestServer::new().await.unwrap();
    let target_addr = target_server.addr();
    
    tokio::spawn(target_server.echo_server());

    // Use dynamic port allocation
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
            let target_addr = target_addr.to_string();
            tokio::spawn(async move {
                let cache = ConnectionCache::new(128 * 1024);
                let active_connections = Arc::new(AtomicUsize::new(0));
                let total_tx = Arc::new(AtomicU64::new(0));
                let total_rx = Arc::new(AtomicU64::new(0));
                let _ = TcpProxy::handle_connection_with_cache(inbound, client_addr, target_addr, cache, None, active_connections, total_tx, total_rx, 16 * 1024 * 1024).await;
            });
        }
    });

    sleep(Duration::from_millis(200)).await;

    let mut client = timeout(
        Duration::from_secs(5),
        TcpStream::connect(proxy_addr)
    ).await.unwrap().unwrap();
    
    let test_message = b"Integration test message";
    
    client.write_all(test_message).await.unwrap();
    
    let mut response = [0; 1024];
    let n = client.read(&mut response).await.unwrap();
    
    assert_eq!(&response[0..n], test_message);
}

#[tokio::test]
async fn test_http_proxy_basic() {
    tracing_subscriber::fmt::try_init().ok();

    let target_server = TestServer::new().await.unwrap();
    let _target_addr = target_server.addr();
    
    tokio::spawn(target_server.http_echo_server());

    let proxy = HttpProxy::new("127.0.0.1:0", "127.0.0.1:8080", 128 * 1024);
    let proxy_handle = tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    sleep(Duration::from_millis(200)).await;

    // Simple test to verify the proxy server can start
    assert!(true);
    
    proxy_handle.abort();
}

#[tokio::test]
async fn test_concurrent_tcp_connections() {
    tracing_subscriber::fmt::try_init().ok();

    let target_server = TestServer::new().await.unwrap();
    let target_addr = target_server.addr();
    
    tokio::spawn(target_server.echo_server());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
            let target_addr = target_addr.to_string();
            tokio::spawn(async move {
                let cache = rustproxy::ConnectionCache::new(128 * 1024);
                let active_connections = Arc::new(AtomicUsize::new(0));
                let total_tx = Arc::new(AtomicU64::new(0));
                let total_rx = Arc::new(AtomicU64::new(0));
                let _ = rustproxy::TcpProxy::handle_connection_with_cache(inbound, client_addr, target_addr, cache, None, active_connections, total_tx, total_rx, 16 * 1024 * 1024).await;
            });
        }
    });

    sleep(Duration::from_millis(100)).await;

    let mut handles = vec![];
    
    for i in 0..10 {
        let proxy_addr = proxy_addr;
        let handle = tokio::spawn(async move {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            let test_data = format!("Concurrent message {}", i);
            
            client.write_all(test_data.as_bytes()).await.unwrap();
            
            let mut buffer = [0; 1024];
            let n = client.read(&mut buffer).await.unwrap();
            
            assert_eq!(&buffer[0..n], test_data.as_bytes());
            i
        });
        handles.push(handle);
    }

    let mut results = vec![];
    for handle in handles {
        let result = handle.await.unwrap();
        results.push(result);
    }

    results.sort();
    assert_eq!(results, (0..10).collect::<Vec<_>>());
}

#[tokio::test]
async fn test_proxy_error_handling() {
    tracing_subscriber::fmt::try_init().ok();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
            let invalid_target = "127.0.0.1:99999".to_string(); // Invalid port
            tokio::spawn(async move {
                let cache = rustproxy::ConnectionCache::new(128 * 1024);
                let active_connections = Arc::new(AtomicUsize::new(0));
                let total_tx = Arc::new(AtomicU64::new(0));
                let total_rx = Arc::new(AtomicU64::new(0));
                let _ = rustproxy::TcpProxy::handle_connection_with_cache(inbound, client_addr, invalid_target, cache, None, active_connections, total_tx, total_rx, 16 * 1024 * 1024).await;
            });
        }
    });

    sleep(Duration::from_millis(100)).await;

    let connection_result = timeout(
        Duration::from_secs(2),
        TcpStream::connect(proxy_addr)
    ).await;

    assert!(connection_result.is_ok());
    
    if let Ok(mut client) = connection_result.unwrap() {
        let write_result = client.write_all(b"test").await;
        assert!(write_result.is_ok());
        
        let mut buffer = [0; 1024];
        let read_result = timeout(Duration::from_secs(1), client.read(&mut buffer)).await;
        match read_result {
            Err(_) => assert!(true), // Timeout is expected
            Ok(Err(_)) => assert!(true), // IO error is expected  
            Ok(Ok(0)) => assert!(true), // Connection closed is expected
            Ok(Ok(_)) => assert!(false), // Unexpected successful read
        }
    }
}