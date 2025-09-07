use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, debug, warn};
use crate::connection_cache::ConnectionCache;

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
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REP_CONN_NOT_ALLOWED: u8 = 0x02;
const SOCKS5_REP_NET_UNREACHABLE: u8 = 0x03;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REP_CONN_REFUSED: u8 = 0x05;
const SOCKS5_REP_TTL_EXPIRED: u8 = 0x06;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

#[derive(Clone)]
pub struct Socks5Proxy {
    bind_addr: String,
    cache: ConnectionCache,
    auth_required: bool,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug)]
struct Socks5Request {
    cmd: u8,
    atyp: u8,
    addr: String,
    port: u16,
}

impl Socks5Proxy {
    pub fn new(bind_addr: &str, cache_size_bytes: usize) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            auth_required: false,
            username: None,
            password: None,
        }
    }

    pub fn with_auth(bind_addr: &str, cache_size_bytes: usize, username: String, password: String) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            cache: ConnectionCache::new(cache_size_bytes),
            auth_required: true,
            username: Some(username),
            password: Some(password),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        let (current_cache, max_cache) = self.cache.get_cache_stats().await;
        
        info!("SOCKS5 proxy listening on {} (cache: {}/{}KB, auth: {})", 
              self.bind_addr, current_cache / 1024, max_cache / 1024, 
              if self.auth_required { "enabled" } else { "disabled" });

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

        Ok(Socks5Request { cmd, atyp, addr, port })
    }

    async fn handle_connect_command(&self, mut client_stream: TcpStream, client_addr: SocketAddr, request: Socks5Request) -> Result<(), Box<dyn std::error::Error>> {
        let target_addr = format!("{}:{}", request.addr, request.port);
        
        debug!("SOCKS5 CONNECT request from {} to {}", client_addr, target_addr);

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
        self.proxy_data(client_stream, target_stream, client_addr, target_addr).await?;

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

    async fn proxy_data(&self, client_stream: TcpStream, target_stream: TcpStream, client_addr: SocketAddr, _target_addr: String) -> Result<(), Box<dyn std::error::Error>> {
        let (mut client_read, mut client_write) = client_stream.into_split();
        let (mut target_read, mut target_write) = target_stream.into_split();

        let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
        let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

        match tokio::try_join!(client_to_target, target_to_client) {
            Ok((bytes_to_target, bytes_to_client)) => {
                info!(
                    "SOCKS5 connection {} closed. Transferred {} bytes to target, {} bytes to client",
                    client_addr, bytes_to_target, bytes_to_client
                );
            }
            Err(e) => {
                error!("Error in SOCKS5 bidirectional copy for {}: {}", client_addr, e);
            }
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

        let proxy = Socks5Proxy::new("127.0.0.1:0", 128 * 1024);
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

        let proxy = Socks5Proxy::with_auth("127.0.0.1:0", 128 * 1024, "testuser".to_string(), "testpass".to_string());
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