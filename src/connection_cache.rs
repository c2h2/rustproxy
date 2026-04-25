use tokio::net::TcpStream;

/// Stub kept for CLI/configuration compatibility.
///
/// An earlier version of this module attempted to pool outbound `TcpStream`s
/// by destination so that subsequent client connections could reuse them.
/// That design is fundamentally unsafe for a forwarding proxy: handing the
/// same outbound socket to two unrelated clients interleaves their byte
/// streams. The pooling code has been removed; `get_connection` always
/// returns `None` and the configured cache size is now purely advisory.
#[derive(Clone)]
pub struct ConnectionCache {
    max_size_bytes: usize,
}

impl ConnectionCache {
    pub fn new(max_size_bytes: usize) -> Self {
        Self { max_size_bytes }
    }

    /// Always returns `None` — kept so call sites compile unchanged.
    /// Reusing outbound TCP sockets across clients would mix their streams,
    /// so this proxy never pools.
    pub async fn get_connection(&self, _target: &str) -> Option<TcpStream> {
        None
    }

    /// Returns `(0, max_size_bytes)` — the proxy never stores anything,
    /// but the CLI still reports the configured size for visibility.
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        (0, self.max_size_bytes)
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

    /// The cache is a deliberate stub: pooling outbound TCP sockets across
    /// unrelated clients would mix their byte streams. Lock that contract
    /// in so a future change can't accidentally restore pooling without
    /// also revisiting this test.
    #[tokio::test]
    async fn get_connection_always_returns_none() {
        let cache = ConnectionCache::new(1024 * 1024);
        assert!(cache.get_connection("anything:1234").await.is_none());

        let zero_cache = ConnectionCache::new(0);
        assert!(zero_cache.get_connection("anything:1234").await.is_none());
    }
}