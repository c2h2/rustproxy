use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct ConnectionCache {
    cache: Arc<tokio::sync::Mutex<HashMap<String, Vec<TcpStream>>>>,
    max_size_bytes: usize,
    current_size_bytes: Arc<tokio::sync::Mutex<usize>>,
}

impl ConnectionCache {
    pub fn new(max_size_bytes: usize) -> Self {
        Self {
            cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            max_size_bytes,
            current_size_bytes: Arc::new(tokio::sync::Mutex::new(0)),
        }
    }

    pub async fn get_connection(&self, target: &str) -> Option<TcpStream> {
        if self.max_size_bytes == 0 {
            return None; // No caching when size is 0
        }

        let mut cache = self.cache.lock().await;
        if let Some(connections) = cache.get_mut(target) {
            if let Some(conn) = connections.pop() {
                let mut current_size = self.current_size_bytes.lock().await;
                *current_size = current_size.saturating_sub(8192); // Estimate 8KB per connection
                debug!("Retrieved cached connection for {}", target);
                return Some(conn);
            }
        }
        None
    }

    pub async fn store_connection(&self, target: &str, connection: TcpStream) {
        if self.max_size_bytes == 0 {
            debug!("Connection caching disabled");
            return; // No caching when size is 0
        }

        let mut current_size = self.current_size_bytes.lock().await;
        if *current_size + 8192 > self.max_size_bytes {
            warn!("Connection cache full ({} bytes), not storing connection", *current_size);
            return; // Cache full
        }

        let mut cache = self.cache.lock().await;
        let connections = cache.entry(target.to_string()).or_insert_with(Vec::new);
        connections.push(connection);
        *current_size += 8192;
        debug!("Stored connection for {} (cache size: {} bytes)", target, *current_size);
    }

    pub async fn get_cache_stats(&self) -> (usize, usize) {
        let current_size = *self.current_size_bytes.lock().await;
        (current_size, self.max_size_bytes)
    }

    pub fn cache_size_kb(&self) -> usize {
        self.max_size_bytes / 1024
    }
}

pub fn parse_cache_size(cache_size_str: &str) -> Result<usize, String> {
    let cache_size_str = cache_size_str.to_lowercase();
    
    if cache_size_str == "0" || cache_size_str == "none" {
        return Ok(0);
    }

    if let Some(size_str) = cache_size_str.strip_suffix("kb") {
        let size: usize = size_str.parse()
            .map_err(|_| format!("Invalid cache size: {}", cache_size_str))?;
        Ok(size * 1024)
    } else if let Some(size_str) = cache_size_str.strip_suffix("mb") {
        let size: usize = size_str.parse()
            .map_err(|_| format!("Invalid cache size: {}", cache_size_str))?;
        Ok(size * 1024 * 1024)
    } else if let Some(size_str) = cache_size_str.strip_suffix("gb") {
        let size: usize = size_str.parse()
            .map_err(|_| format!("Invalid cache size: {}", cache_size_str))?;
        Ok(size * 1024 * 1024 * 1024)
    } else {
        // Assume bytes if no suffix
        cache_size_str.parse()
            .map_err(|_| format!("Invalid cache size: {}. Use format like '128kb', '1mb', '8mb' or '0' for no cache", cache_size_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cache_size() {
        assert_eq!(parse_cache_size("0").unwrap(), 0);
        assert_eq!(parse_cache_size("none").unwrap(), 0);
        assert_eq!(parse_cache_size("128kb").unwrap(), 128 * 1024);
        assert_eq!(parse_cache_size("1mb").unwrap(), 1024 * 1024);
        assert_eq!(parse_cache_size("8MB").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_cache_size("1024").unwrap(), 1024);
        
        assert!(parse_cache_size("invalid").is_err());
        assert!(parse_cache_size("128xyz").is_err());
    }

    #[tokio::test]
    async fn test_connection_cache_basic() {
        use tokio::net::TcpListener;
        
        let cache = ConnectionCache::new(1024 * 1024); // 1MB cache
        
        // Create a test server to get a valid TcpStream
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Start a simple echo server
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0; 1024];
                if let Ok(_) = stream.try_read(&mut buf) {
                    // Just close the connection
                }
            }
        });
        
        let target = addr.to_string();
        let connection = TcpStream::connect(&target).await.unwrap();
        
        // Test storing and retrieving a connection
        cache.store_connection(&target, connection).await;
        let retrieved = cache.get_connection(&target).await;
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_cache_size_limit() {
        let cache = ConnectionCache::new(0); // No cache
        
        // Even if we try to store, it should not be retrievable
        cache.store_connection("test", TcpStream::connect("127.0.0.1:22").await.unwrap_or_else(|_| {
            // If connection fails, create a dummy - this test is about cache behavior
            panic!("Need a valid connection for testing")
        })).await;
        
        let retrieved = cache.get_connection("test").await;
        assert!(retrieved.is_none()); // Should be None because cache size is 0
    }
}