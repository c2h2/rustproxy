use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, debug, warn};
use crate::connection_cache::ConnectionCache;
use crate::stats::StatsCollector;

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_AUTH_USER_PASS: u8 = 0x02;
const SOCKS5_NO_ACCEPTABLE_AUTH: u8 = 0xFF;

const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_CMD_BIND: u8 = 0x02;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;

#[derive(Clone)]
pub struct Socks5Proxy {
    bind_addr: String,
    cache: ConnectionCache,
    auth_required: bool,
    username: Option<String>,
    password: Option<String>,
    stats: Option<Arc<StatsCollector>>,
    buffer_size: usize,
}

#[derive(Debug)]
struct Socks5Request {
    cmd: u8,
    addr: String,
    port: u16,
}

impl Socks5Proxy {
    #[allow(dead_code)]
    pub fn new(bind_addr: &str, cache_size_bytes: usize, buffer_size: usize) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            auth_required: false,
            username: None,
            password: None,
            stats: None,
            buffer_size,
        }
    }

    #[allow(dead_code)]
    pub fn with_auth(bind_addr: &str, cache_size_bytes: usize, username: String, password: String, buffer_size: usize) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            auth_required: true,
            username: Some(username),
            password: Some(password),
            stats: None,
            buffer_size,
        }
    }

    pub fn with_stats(bind_addr: &str, cache_size_bytes: usize, manager_addr: Option<SocketAddr>, buffer_size: usize) -> Self {
        let stats = manager_addr.map(|addr| {
            Arc::new(StatsCollector::new("socks5", bind_addr, Some(addr)))
        });

        Self {
            bind_addr: bind_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            auth_required: false,
            username: None,
            password: None,
            stats,
            buffer_size,
        }
    }

    pub fn with_auth_and_stats(bind_addr: &str, cache_size_bytes: usize, username: String, password: String, manager_addr: Option<SocketAddr>, buffer_size: usize) -> Self {
        let stats = manager_addr.map(|addr| {
            Arc::new(StatsCollector::new("socks5", bind_addr, Some(addr)))
        });

        Self {
            bind_addr: bind_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            auth_required: true,
            username: Some(username),
            password: Some(password),
            stats,
            buffer_size,
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        let (current_cache, max_cache) = self.cache.get_cache_stats().await;
        
        info!("SOCKS5 proxy listening on {} (cache: {}/{}KB, auth: {})", 
              self.bind_addr, current_cache / 1024, max_cache / 1024, 
              if self.auth_required { "enabled" } else { "disabled" });
        
        // Start stats reporting if enabled
        if let Some(ref stats) = self.stats {
            stats.clone().start_reporting().await;
        }

        loop {
            let (inbound, client_addr) = listener.accept().await?;
            let proxy = self.clone();

            tokio::spawn(async move {
                if let Err(e) = proxy.handle_connection(inbound, client_addr).await {
                    error!("Error handling SOCKS5 connection from {}: {}", client_addr, e);
                }
            });
        }
    }

    async fn handle_connection(&self, mut stream: TcpStream, client_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        debug!("New SOCKS5 connection from {}", client_addr);

        // Step 1: Authentication negotiation
        self.handle_auth_negotiation(&mut stream).await?;

        // Step 2: Handle SOCKS5 request
        let request = self.parse_socks5_request(&mut stream).await?;
        
        match request.cmd {
            SOCKS5_CMD_CONNECT => {
                self.handle_connect_command(stream, client_addr, request).await?;
            }
            SOCKS5_CMD_BIND => {
                self.send_error_response(&mut stream, SOCKS5_REP_CMD_NOT_SUPPORTED).await?;
                return Err("BIND command not supported".into());
            }
            SOCKS5_CMD_UDP_ASSOCIATE => {
                self.send_error_response(&mut stream, SOCKS5_REP_CMD_NOT_SUPPORTED).await?;
                return Err("UDP ASSOCIATE command not supported".into());
            }
            _ => {
                self.send_error_response(&mut stream, SOCKS5_REP_CMD_NOT_SUPPORTED).await?;
                return Err("Unsupported command".into());
            }
        }

        Ok(())
    }

    async fn handle_auth_negotiation(&self, stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        // Read authentication methods
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        
        if buf[0] != SOCKS5_VERSION {
            return Err("Invalid SOCKS version".into());
        }
        
        let nmethods = buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;
        
        // Choose authentication method
        let chosen_method = if self.auth_required {
            if methods.contains(&SOCKS5_AUTH_USER_PASS) {
                SOCKS5_AUTH_USER_PASS
            } else {
                SOCKS5_NO_ACCEPTABLE_AUTH
            }
        } else if methods.contains(&SOCKS5_NO_AUTH) {
            SOCKS5_NO_AUTH
        } else {
            SOCKS5_NO_ACCEPTABLE_AUTH
        };

        // Send method selection response
        let response = [SOCKS5_VERSION, chosen_method];
        stream.write_all(&response).await?;

        if chosen_method == SOCKS5_NO_ACCEPTABLE_AUTH {
            return Err("No acceptable authentication method".into());
        }

        // Handle username/password authentication if required
        if chosen_method == SOCKS5_AUTH_USER_PASS {
            self.handle_user_pass_auth(stream).await?;
        }

        Ok(())
    }

    async fn handle_user_pass_auth(&self, stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        // Read username/password authentication request
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;
        
        if buf[0] != 0x01 {  // Username/password auth version
            return Err("Invalid username/password auth version".into());
        }

        // Read username
        stream.read_exact(&mut buf).await?;
        let username_len = buf[0] as usize;
        let mut username_buf = vec![0u8; username_len];
        stream.read_exact(&mut username_buf).await?;
        let username = String::from_utf8(username_buf)?;

        // Read password
        stream.read_exact(&mut buf).await?;
        let password_len = buf[0] as usize;
        let mut password_buf = vec![0u8; password_len];
        stream.read_exact(&mut password_buf).await?;
        let password = String::from_utf8(password_buf)?;

        // Validate credentials
        let auth_success = if let (Some(ref expected_user), Some(ref expected_pass)) = (&self.username, &self.password) {
            username == *expected_user && password == *expected_pass
        } else {
            false
        };

        // Send authentication response
        let response = [0x01, if auth_success { 0x00 } else { 0x01 }];
        stream.write_all(&response).await?;

        if !auth_success {
            return Err("Authentication failed".into());
        }

        debug!("SOCKS5 authentication successful for user: {}", username);
        Ok(())
    }

    async fn parse_socks5_request(&self, stream: &mut TcpStream) -> Result<Socks5Request, Box<dyn std::error::Error>> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VERSION {
            return Err("Invalid SOCKS version in request".into());
        }

        let cmd = buf[1];
        let _rsv = buf[2]; // Reserved, must be 0
        let atyp = buf[3];

        let (addr, port) = match atyp {
            SOCKS5_ATYP_IPV4 => {
                let mut addr_buf = [0u8; 4];
                stream.read_exact(&mut addr_buf).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                
                let ip = Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                let port = u16::from_be_bytes(port_buf);
                (ip.to_string(), port)
            }
            SOCKS5_ATYP_IPV6 => {
                let mut addr_buf = [0u8; 16];
                stream.read_exact(&mut addr_buf).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                
                let ip = Ipv6Addr::from(addr_buf);
                let port = u16::from_be_bytes(port_buf);
                (ip.to_string(), port)
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                
                let mut domain_buf = vec![0u8; domain_len];
                stream.read_exact(&mut domain_buf).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                
                let domain = String::from_utf8(domain_buf)?;
                let port = u16::from_be_bytes(port_buf);
                (domain, port)
            }
            _ => {
                return Err("Unsupported address type".into());
            }
        };

        Ok(Socks5Request { cmd, addr, port })
    }

    async fn handle_connect_command(&self, mut client_stream: TcpStream, client_addr: SocketAddr, request: Socks5Request) -> Result<(), Box<dyn std::error::Error>> {
        let target_addr = format!("{}:{}", request.addr, request.port);
        
        debug!("SOCKS5 CONNECT request from {} to {}", client_addr, target_addr);
        
        // Create stats connection ID if stats are enabled
        let conn_id = if let Some(ref stats) = self.stats {
            Some(stats.new_connection(client_addr, target_addr.clone()).await)
        } else {
            None
        };

        // Try to get a cached connection first
        let target_stream = match self.cache.get_connection(&target_addr).await {
            Some(conn) => {
                debug!("Using cached connection for {}", target_addr);
                conn
            }
            None => {
                debug!("Creating new connection to {}", target_addr);
                match TcpStream::connect(&target_addr).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        warn!("Failed to connect to {}: {}", target_addr, e);
                        
                        // Close connection in stats if enabled
                        if let (Some(ref stats), Some(ref conn_id)) = (&self.stats, &conn_id) {
                            stats.close_connection(conn_id).await;
                        }
                        
                        self.send_error_response(&mut client_stream, SOCKS5_REP_HOST_UNREACHABLE).await?;
                        return Err(e.into());
                    }
                }
            }
        };

        // Send success response
        self.send_connect_response(&mut client_stream, &target_stream).await?;
        
        info!("SOCKS5 connection established: {} -> {}", client_addr, target_addr);

        // Start proxying data
        self.proxy_data(client_stream, target_stream, client_addr, target_addr, self.stats.clone(), conn_id).await?;

        Ok(())
    }

    async fn send_connect_response(&self, stream: &mut TcpStream, target_stream: &TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        let local_addr = target_stream.local_addr()?;
        
        let mut response = vec![SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0x00]; // VER, REP, RSV

        match local_addr.ip() {
            IpAddr::V4(ip) => {
                response.push(SOCKS5_ATYP_IPV4);
                response.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                response.push(SOCKS5_ATYP_IPV6);
                response.extend_from_slice(&ip.octets());
            }
        }
        
        response.extend_from_slice(&local_addr.port().to_be_bytes());
        
        stream.write_all(&response).await?;
        Ok(())
    }

    async fn send_error_response(&self, stream: &mut TcpStream, error_code: u8) -> Result<(), Box<dyn std::error::Error>> {
        let response = [
            SOCKS5_VERSION,
            error_code,
            0x00, // RSV
            SOCKS5_ATYP_IPV4,
            0x00, 0x00, 0x00, 0x00, // IP 0.0.0.0
            0x00, 0x00, // Port 0
        ];
        
        stream.write_all(&response).await?;
        Ok(())
    }

    async fn proxy_data(&self, client_stream: TcpStream, target_stream: TcpStream, client_addr: SocketAddr, _target_addr: String, stats: Option<Arc<StatsCollector>>, conn_id: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let (mut client_read, mut client_write) = client_stream.into_split();
        let (mut target_read, mut target_write) = target_stream.into_split();

        // Client→Target: direct copy (no buffering needed)
        let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);

        // Target→Client: buffered via duplex pipe so reads from target
        // are decoupled from slow client writes
        let buffer_size = self.buffer_size;
        let (mut duplex_w, mut duplex_r) = tokio::io::duplex(buffer_size);
        let t2buf = tokio::spawn(async move {
            tokio::io::copy(&mut target_read, &mut duplex_w).await
        });
        let buf2c = tokio::io::copy(&mut duplex_r, &mut client_write);

        // Use join to capture partial byte counts even on failures
        let (result1, r_t2buf, r_buf2c) = tokio::join!(client_to_target, t2buf, buf2c);

        // Extract byte counts from results, defaulting to 0 on error
        let bytes_to_target = match &result1 {
            Ok(bytes) => *bytes,
            Err(e1) => {
                debug!("Client-to-target copy error for {}: {}", client_addr, e1);
                0
            }
        };
        if let Err(e) = &r_t2buf {
            debug!("Target->Buffer task error for {}: {}", client_addr, e);
        } else if let Ok(Err(e)) = &r_t2buf {
            debug!("Target->Buffer copy error for {}: {}", client_addr, e);
        }
        let bytes_to_client = match &r_buf2c {
            Ok(bytes) => *bytes,
            Err(e2) => {
                debug!("Buffer-to-client copy error for {}: {}", client_addr, e2);
                0
            }
        };

        info!(
            "SOCKS5 connection {} closed. Transferred {} bytes to target, {} bytes to client",
            client_addr, bytes_to_target, bytes_to_client
        );

        // Update stats with actual bytes transferred (even if partial)
        if let (Some(ref stats), Some(ref conn_id)) = (&stats, &conn_id) {
            stats.update_connection(conn_id, bytes_to_target, bytes_to_client).await;
            stats.close_connection(conn_id).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockTcpServer;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_socks5_proxy_basic() {
        tracing_subscriber::fmt::try_init().ok();

        let mock_server = MockTcpServer::new().await.unwrap();
        let target_addr = mock_server.addr();
        
        tokio::spawn(mock_server.echo_server());

        let proxy = Socks5Proxy::new("127.0.0.1:0", 128 * 1024, 16 * 1024 * 1024);
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    let _ = proxy.handle_connection(inbound, client_addr).await;
                });
            }
        });

        sleep(Duration::from_millis(100)).await;

        // Test SOCKS5 connection
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        
        // Send authentication negotiation (no auth)
        client.write_all(&[SOCKS5_VERSION, 1, SOCKS5_NO_AUTH]).await.unwrap();
        
        // Read auth response
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], SOCKS5_VERSION);
        assert_eq!(buf[1], SOCKS5_NO_AUTH);

        // Send CONNECT request
        let target_ip = match target_addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => panic!("Expected IPv4 address"),
        };
        
        let mut request = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_IPV4];
        request.extend_from_slice(&target_ip.octets());
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        
        client.write_all(&request).await.unwrap();
        
        // Read connect response
        let mut response = [0u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], SOCKS5_VERSION);
        assert_eq!(response[1], SOCKS5_REP_SUCCESS);

        // Test data transfer
        let test_data = b"Hello, SOCKS5!";
        client.write_all(test_data).await.unwrap();
        
        let mut buffer = [0; 1024];
        let n = client.read(&mut buffer).await.unwrap();
        
        assert_eq!(&buffer[0..n], test_data);
    }

    #[tokio::test]
    async fn test_socks5_proxy_with_auth() {
        tracing_subscriber::fmt::try_init().ok();

        let mock_server = MockTcpServer::new().await.unwrap();
        let target_addr = mock_server.addr();
        
        tokio::spawn(mock_server.echo_server());

        let proxy = Socks5Proxy::with_auth("127.0.0.1:0", 128 * 1024, "testuser".to_string(), "testpass".to_string(), 16 * 1024 * 1024);
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    let _ = proxy.handle_connection(inbound, client_addr).await;
                });
            }
        });

        sleep(Duration::from_millis(100)).await;

        // Test SOCKS5 connection with authentication
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        
        // Send authentication negotiation (username/password)
        client.write_all(&[SOCKS5_VERSION, 1, SOCKS5_AUTH_USER_PASS]).await.unwrap();
        
        // Read auth response
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], SOCKS5_VERSION);
        assert_eq!(buf[1], SOCKS5_AUTH_USER_PASS);

        // Send username/password
        let username = b"testuser";
        let password = b"testpass";
        let mut auth_request = vec![0x01, username.len() as u8];
        auth_request.extend_from_slice(username);
        auth_request.push(password.len() as u8);
        auth_request.extend_from_slice(password);
        
        client.write_all(&auth_request).await.unwrap();
        
        // Read auth response
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x00); // Success

        // Send CONNECT request
        let target_ip = match target_addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => panic!("Expected IPv4 address"),
        };
        
        let mut request = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_IPV4];
        request.extend_from_slice(&target_ip.octets());
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        
        client.write_all(&request).await.unwrap();
        
        // Read connect response
        let mut response = [0u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], SOCKS5_VERSION);
        assert_eq!(response[1], SOCKS5_REP_SUCCESS);

        // Test data transfer
        let test_data = b"Hello, SOCKS5 with auth!";
        client.write_all(test_data).await.unwrap();
        
        let mut buffer = [0; 1024];
        let n = client.read(&mut buffer).await.unwrap();
        
        assert_eq!(&buffer[0..n], test_data);
    }
}