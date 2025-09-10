use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tracing::{error, info, debug, warn};
use crate::connection_cache::ConnectionCache;
use crate::stats::StatsCollector;

pub struct TcpProxy {
    bind_addr: String,
    target_addr: String,
    cache: ConnectionCache,
    stats: Option<Arc<StatsCollector>>,
    active_connections: Arc<AtomicUsize>,
    max_connections: usize,
}

impl TcpProxy {
    #[allow(dead_code)]
    pub fn new(bind_addr: &str, target_addr: &str, cache_size_bytes: usize) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            stats: None,
            active_connections: Arc::new(AtomicUsize::new(0)),
            max_connections: 10000, // Default max connections
        }
    }
    
    pub fn with_stats(bind_addr: &str, target_addr: &str, cache_size_bytes: usize, manager_addr: Option<SocketAddr>) -> Self {
        let stats = manager_addr.map(|addr| {
            Arc::new(StatsCollector::new("tcp", bind_addr, Some(addr)))
        });
        
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            stats,
            active_connections: Arc::new(AtomicUsize::new(0)),
            max_connections: 10000, // Default max connections
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        let (current_cache, max_cache) = self.cache.get_cache_stats().await;
        info!("TCP proxy listening on {} -> {} (cache: {}/{}KB, max connections: {})", 
              self.bind_addr, self.target_addr, current_cache / 1024, max_cache / 1024, self.max_connections);
        
        // Start stats reporting if enabled
        if let Some(stats) = &self.stats {
            stats.clone().start_reporting().await;
        }

        loop {
            match listener.accept().await {
                Ok((inbound, client_addr)) => {
                    let current_connections = self.active_connections.load(Ordering::Relaxed);
                    
                    // Check if we've reached the connection limit
                    if current_connections >= self.max_connections {
                        warn!("Connection limit reached ({}/{}), rejecting connection from {}", 
                              current_connections, self.max_connections, client_addr);
                        drop(inbound); // Close the connection immediately
                        continue;
                    }
                    
                    let target_addr = self.target_addr.clone();
                    let cache = self.cache.clone();
                    let stats = self.stats.clone();
                    let active_connections = self.active_connections.clone();
                    
                    // Increment active connections counter
                    active_connections.fetch_add(1, Ordering::Relaxed);
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection_with_cache(
                            inbound, client_addr, target_addr, cache, stats, active_connections.clone()
                        ).await {
                            error!("Error handling connection from {}: {}", client_addr, e);
                        }
                        
                        // Decrement active connections counter when done
                        active_connections.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    // Add a small delay to prevent tight loop on persistent errors
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    pub async fn handle_connection_with_cache(
        mut inbound: TcpStream,
        client_addr: SocketAddr,
        target_addr: String,
        cache: ConnectionCache,
        stats: Option<Arc<StatsCollector>>,
        _active_connections: Arc<AtomicUsize>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create stats connection ID if stats are enabled
        let conn_id = if let Some(ref stats) = stats {
            Some(stats.new_connection(client_addr, target_addr.clone()).await)
        } else {
            None
        };
        
        // Try to get a cached connection first
        let mut outbound = match cache.get_connection(&target_addr).await {
            Some(conn) => {
                debug!("Using cached connection for {} -> {}", client_addr, target_addr);
                conn
            }
            None => {
                debug!("Creating new connection for {} -> {}", client_addr, target_addr);
                // Add timeout to prevent hanging connections
                match timeout(Duration::from_secs(10), TcpStream::connect(&target_addr)).await {
                    Ok(Ok(conn)) => conn,
                    Ok(Err(e)) => {
                        error!("Failed to connect to {}: {}", target_addr, e);
                        if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                            stats.close_connection(conn_id).await;
                        }
                        return Err(e.into());
                    }
                    Err(_) => {
                        error!("Connection timeout to {}", target_addr);
                        if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                            stats.close_connection(conn_id).await;
                        }
                        return Err("Connection timeout".into());
                    }
                }
            }
        };

        info!("Proxying connection from {} to {}", client_addr, target_addr);

        // Split both connections
        let (mut ri, mut wi) = inbound.split();
        let (mut ro, mut wo) = outbound.split();

        // Perform bidirectional copy
        let client_to_server = tokio::io::copy(&mut ri, &mut wo);
        let server_to_client = tokio::io::copy(&mut ro, &mut wi);

        let result = tokio::try_join!(client_to_server, server_to_client);
        
        // Properly close connections and update stats
        match result {
            Ok((bytes_to_server, bytes_to_client)) => {
                info!(
                    "Connection {} closed. Transferred {} bytes to server, {} bytes to client",
                    client_addr, bytes_to_server, bytes_to_client
                );
                
                // Update stats if enabled
                if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                    stats.update_connection(conn_id, bytes_to_server, bytes_to_client).await;
                    stats.close_connection(conn_id).await;
                }
            }
            Err(e) => {
                debug!("Connection ended for {}: {}", client_addr, e);
                
                // Close connection in stats if enabled
                if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
                    stats.close_connection(conn_id).await;
                }
            }
        }
        
        // Reassemble and try to return connection to cache
        // Note: We need to reassemble the streams back into a TcpStream
        // Since we can't easily reassemble split streams, we'll skip caching for now
        // This ensures proper cleanup of file descriptors
        
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockTcpServer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_tcp_proxy_basic_functionality() {
        tracing_subscriber::fmt::try_init().ok();

        let mock_server = MockTcpServer::new().await.unwrap();
        let target_addr = mock_server.addr();
        
        tokio::spawn(mock_server.echo_server());

        let _proxy = TcpProxy::new("127.0.0.1:0", &target_addr.to_string(), 128 * 1024);
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
                let target_addr = target_addr.to_string();
                tokio::spawn(async move {
                    let cache = ConnectionCache::new(128 * 1024);
                    let active_connections = Arc::new(AtomicUsize::new(0));
                    let _ = TcpProxy::handle_connection_with_cache(inbound, client_addr, target_addr, cache, None, active_connections).await;
                });
            }
        });

        sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let test_data = b"Hello, TCP Proxy!";
        
        client.write_all(test_data).await.unwrap();
        
        let mut buffer = [0; 1024];
        let n = client.read(&mut buffer).await.unwrap();
        
        assert_eq!(&buffer[0..n], test_data);
    }

    #[tokio::test]
    async fn test_tcp_proxy_multiple_connections() {
        tracing_subscriber::fmt::try_init().ok();

        let mock_server = MockTcpServer::new().await.unwrap();
        let target_addr = mock_server.addr();
        
        tokio::spawn(mock_server.echo_server());

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
                let target_addr = target_addr.to_string();
                tokio::spawn(async move {
                    let cache = ConnectionCache::new(128 * 1024);
                    let active_connections = Arc::new(AtomicUsize::new(0));
                    let _ = TcpProxy::handle_connection_with_cache(inbound, client_addr, target_addr, cache, None, active_connections).await;
                });
            }
        });

        sleep(Duration::from_millis(100)).await;

        let mut handles = vec![];
        
        for i in 0..5 {
            let proxy_addr = proxy_addr;
            let handle = tokio::spawn(async move {
                let mut client = TcpStream::connect(proxy_addr).await.unwrap();
                let test_data = format!("Message {}", i);
                
                client.write_all(test_data.as_bytes()).await.unwrap();
                
                let mut buffer = [0; 1024];
                let n = client.read(&mut buffer).await.unwrap();
                
                assert_eq!(&buffer[0..n], test_data.as_bytes());
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_tcp_proxy_large_data() {
        tracing_subscriber::fmt::try_init().ok();

        let mock_server = MockTcpServer::new().await.unwrap();
        let target_addr = mock_server.addr();
        
        tokio::spawn(mock_server.echo_server());

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
                let target_addr = target_addr.to_string();
                tokio::spawn(async move {
                    let cache = ConnectionCache::new(128 * 1024);
                    let active_connections = Arc::new(AtomicUsize::new(0));
                    let _ = TcpProxy::handle_connection_with_cache(inbound, client_addr, target_addr, cache, None, active_connections).await;
                });
            }
        });

        sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let test_data = vec![b'A'; 8192]; // 8KB of data
        
        client.write_all(&test_data).await.unwrap();
        
        let mut buffer = vec![0; 8192];
        let mut total_read = 0;
        
        while total_read < test_data.len() {
            let n = client.read(&mut buffer[total_read..]).await.unwrap();
            if n == 0 { break; }
            total_read += n;
        }
        
        assert_eq!(total_read, test_data.len());
        assert_eq!(&buffer[0..total_read], test_data.as_slice());
    }
}