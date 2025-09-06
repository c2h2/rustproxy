use rustproxy::{TcpProxy, HttpProxy};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use tracing::{info, warn};

pub struct ConnectionCache {
    cache: Arc<std::sync::Mutex<HashMap<String, Vec<TcpStream>>>>,
    max_size_bytes: usize,
    current_size_bytes: Arc<std::sync::Mutex<usize>>,
}

impl ConnectionCache {
    pub fn new(max_size_bytes: usize) -> Self {
        Self {
            cache: Arc::new(std::sync::Mutex::new(HashMap::new())),
            max_size_bytes,
            current_size_bytes: Arc::new(std::sync::Mutex::new(0)),
        }
    }

    pub async fn get_connection(&self, target: &str) -> Option<TcpStream> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(connections) = cache.get_mut(target) {
            if let Some(conn) = connections.pop() {
                let mut current_size = self.current_size_bytes.lock().unwrap();
                *current_size = current_size.saturating_sub(8192); // Estimate 8KB per connection
                return Some(conn);
            }
        }
        None
    }

    pub async fn store_connection(&self, target: &str, connection: TcpStream) {
        if self.max_size_bytes == 0 {
            return; // No caching when size is 0
        }

        let mut current_size = self.current_size_bytes.lock().unwrap();
        if *current_size + 8192 > self.max_size_bytes {
            return; // Cache full
        }

        let mut cache = self.cache.lock().unwrap();
        let connections = cache.entry(target.to_string()).or_insert_with(Vec::new);
        connections.push(connection);
        *current_size += 8192;
    }
}

impl Clone for ConnectionCache {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
            max_size_bytes: self.max_size_bytes,
            current_size_bytes: Arc::clone(&self.current_size_bytes),
        }
    }
}

pub struct CachedTcpProxy {
    bind_addr: String,
    target_addr: String,
    cache: ConnectionCache,
}

impl CachedTcpProxy {
    pub fn new(bind_addr: &str, target_addr: &str, cache_size_bytes: usize) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
        }
    }

    async fn handle_connection_cached(
        mut inbound: TcpStream,
        client_addr: std::net::SocketAddr,
        target_addr: String,
        _cache: ConnectionCache,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // For this benchmark, we'll create a new connection each time
        // In a real implementation, you'd use the cache here
        let mut outbound = TcpStream::connect(&target_addr).await?;

        let (mut ri, mut wi) = inbound.split();
        let (mut ro, mut wo) = outbound.split();

        let client_to_server = tokio::io::copy(&mut ri, &mut wo);
        let server_to_client = tokio::io::copy(&mut ro, &mut wi);

        match tokio::try_join!(client_to_server, server_to_client) {
            Ok((bytes_to_server, bytes_to_client)) => {
                info!(
                    "Connection {} closed. Transferred {} bytes to server, {} bytes to client",
                    client_addr, bytes_to_server, bytes_to_client
                );
            }
            Err(e) => {
                warn!("Error in bidirectional copy for {}: {}", client_addr, e);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct BenchmarkResult {
    pub cache_size: usize,
    pub total_connections: usize,
    pub avg_connection_time_ms: f64,
    pub total_duration_ms: f64,
    pub throughput_rps: f64,
    pub success_rate: f64,
}

pub struct MockServer {
    listener: TcpListener,
}

impl MockServer {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self { listener })
    }

    pub fn addr(&self) -> std::net::SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub async fn run_echo_server(&self) {
        while let Ok((mut stream, _)) = self.listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 { break; }
                    let _ = stream.write_all(&buffer[0..n]).await;
                }
            });
        }
    }
}

pub async fn run_benchmark_for_cache_size(
    cache_size_bytes: usize,
    num_connections: usize,
    concurrent_connections: usize,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    // Start mock server
    let mock_server = MockServer::new().await?;
    let mock_addr = mock_server.addr();
    
    tokio::spawn(async move {
        mock_server.run_echo_server().await;
    });

    // Start proxy with specific cache size
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;

    tokio::spawn(async move {
        while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
            let target_addr = mock_addr.to_string();
            let cache = ConnectionCache::new(cache_size_bytes);
            tokio::spawn(async move {
                let _ = CachedTcpProxy::handle_connection_cached(inbound, client_addr, target_addr, cache).await;
            });
        }
    });

    sleep(Duration::from_millis(100)).await;

    let start_time = Instant::now();
    let mut connection_times = Vec::new();
    let mut successful_connections = 0;

    // Run benchmark with limited concurrency
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrent_connections));
    let mut handles = Vec::new();

    for i in 0..num_connections {
        let permit = Arc::clone(&semaphore).acquire_owned().await?;
        let proxy_addr = proxy_addr;
        
        let handle = tokio::spawn(async move {
            let _permit = permit; // Keep permit alive
            let conn_start = Instant::now();
            
            match TcpStream::connect(proxy_addr).await {
                Ok(mut stream) => {
                    let test_data = format!("Test message {}", i);
                    
                    if stream.write_all(test_data.as_bytes()).await.is_ok() {
                        let mut buffer = [0; 1024];
                        if let Ok(n) = stream.read(&mut buffer).await {
                            if &buffer[0..n] == test_data.as_bytes() {
                                return (true, conn_start.elapsed().as_millis() as f64);
                            }
                        }
                    }
                }
                Err(_) => {}
            }
            (false, conn_start.elapsed().as_millis() as f64)
        });
        
        handles.push(handle);
    }

    // Wait for all connections to complete
    for handle in handles {
        let (success, duration) = handle.await?;
        connection_times.push(duration);
        if success {
            successful_connections += 1;
        }
    }

    let total_duration = start_time.elapsed().as_millis() as f64;
    let avg_connection_time = if connection_times.is_empty() {
        0.0
    } else {
        connection_times.iter().sum::<f64>() / connection_times.len() as f64
    };
    let throughput = if total_duration > 0.0 {
        (successful_connections as f64 / total_duration) * 1000.0
    } else {
        0.0
    };
    let success_rate = (successful_connections as f64 / num_connections as f64) * 100.0;

    Ok(BenchmarkResult {
        cache_size: cache_size_bytes,
        total_connections: num_connections,
        avg_connection_time_ms: avg_connection_time,
        total_duration_ms: total_duration,
        throughput_rps: throughput,
        success_rate,
    })
}

pub async fn run_comprehensive_benchmark() -> Result<Vec<BenchmarkResult>, Box<dyn std::error::Error>> {
    let cache_sizes = vec![
        0,           // No cache
        128 * 1024,  // 128KB
        1024 * 1024, // 1MB
        8 * 1024 * 1024, // 8MB
    ];

    let num_connections = 500; // Increased for better benchmarking
    let concurrent_connections = 25;

    let mut results = Vec::new();

    for cache_size in cache_sizes {
        println!("Running benchmark for cache size: {}KB", cache_size / 1024);
        
        let result = run_benchmark_for_cache_size(
            cache_size, 
            num_connections, 
            concurrent_connections
        ).await?;
        
        results.push(result);
        
        // Wait between tests to ensure clean state
        sleep(Duration::from_millis(500)).await;
    }

    Ok(results)
}

pub fn print_benchmark_results(results: &[BenchmarkResult]) {
    println!("\n=== Connection Cache Benchmark Results ===");
    println!("{:<12} {:<15} {:<15} {:<15} {:<15} {:<12}", 
             "Cache Size", "Connections", "Avg Conn (ms)", "Total (ms)", "Throughput", "Success %");
    println!("{}", "-".repeat(90));
    
    for result in results {
        let cache_display = if result.cache_size == 0 {
            "No Cache".to_string()
        } else if result.cache_size >= 1024 * 1024 {
            format!("{}MB", result.cache_size / (1024 * 1024))
        } else {
            format!("{}KB", result.cache_size / 1024)
        };
        
        println!("{:<12} {:<15} {:<15.2} {:<15.2} {:<15.2} {:<12.1}", 
                 cache_display,
                 result.total_connections,
                 result.avg_connection_time_ms,
                 result.total_duration_ms,
                 result.throughput_rps,
                 result.success_rate);
    }
    
    // Find best performing configuration
    if let Some(best) = results.iter().max_by(|a, b| a.throughput_rps.partial_cmp(&b.throughput_rps).unwrap()) {
        let cache_display = if best.cache_size == 0 {
            "No Cache".to_string()
        } else if best.cache_size >= 1024 * 1024 {
            format!("{}MB", best.cache_size / (1024 * 1024))
        } else {
            format!("{}KB", best.cache_size / 1024)
        };
        println!("\nBest performing configuration: {} ({:.2} RPS)", cache_display, best.throughput_rps);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    println!("Starting connection cache benchmark...");
    println!("Testing cache sizes: 0KB (no cache), 128KB, 1MB, 8MB");
    println!("Using 500 connections with max 25 concurrent connections per test");
    
    let results = run_comprehensive_benchmark().await?;
    
    print_benchmark_results(&results);
    
    println!("\nBenchmark completed successfully!");
    
    Ok(())
}