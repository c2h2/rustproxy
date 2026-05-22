use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
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
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
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
                self.handle_udp_associate(stream, client_addr, request).await?;
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
                match crate::dns::tcp_connect(&target_addr).await {
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

    async fn handle_udp_associate(
        &self,
        mut control: TcpStream,
        client_tcp_addr: SocketAddr,
        request: Socks5Request,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Bind the client-facing relay UDP socket on the same local IP that the
        // control TCP connection arrived on, so the BND.ADDR we return is
        // reachable from the client.
        let local_ip = control.local_addr()?.ip();
        let inbound = match UdpSocket::bind(SocketAddr::new(local_ip, 0)).await {
            Ok(s) => s,
            Err(e) => {
                self.send_error_response(&mut control, SOCKS5_REP_GENERAL_FAILURE).await?;
                return Err(format!("failed to bind UDP relay socket: {}", e).into());
            }
        };
        let bnd_addr = inbound.local_addr()?;

        // Outbound sockets toward targets. Best-effort dual stack.
        let outbound_v4 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .await
            .ok()
            .map(Arc::new);
        let outbound_v6 = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
            .await
            .ok()
            .map(Arc::new);

        if outbound_v4.is_none() && outbound_v6.is_none() {
            self.send_error_response(&mut control, SOCKS5_REP_GENERAL_FAILURE).await?;
            return Err("could not bind any outbound UDP socket".into());
        }

        // Reply to the client with BND.ADDR / BND.PORT
        self.send_udp_associate_response(&mut control, bnd_addr).await?;

        // Parse the announced client UDP source from the ASSOCIATE request.
        // Per RFC 1928, if the client knows its source it provides DST.ADDR/PORT;
        // otherwise it sends zeros and we lock onto the first observed source.
        let announced: Option<SocketAddr> = match request.addr.parse::<IpAddr>() {
            Ok(ip) if !ip.is_unspecified() && request.port != 0 => {
                Some(SocketAddr::new(ip, request.port))
            }
            _ => None,
        };

        let inbound = Arc::new(inbound);
        let locked_client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(announced));

        info!(
            "SOCKS5 UDP ASSOCIATE: control={} relay={} announced_client={:?}",
            client_tcp_addr, bnd_addr, announced
        );

        let conn_id = if let Some(ref stats) = self.stats {
            Some(
                stats
                    .new_connection(client_tcp_addr, format!("udp-assoc:{}", bnd_addr))
                    .await,
            )
        } else {
            None
        };

        let forward = tokio::spawn(udp_forward_task(
            inbound.clone(),
            outbound_v4.clone(),
            outbound_v6.clone(),
            locked_client.clone(),
        ));

        let reverse_v4 = outbound_v4.clone().map(|sock| {
            tokio::spawn(udp_reverse_task(sock, inbound.clone(), locked_client.clone()))
        });
        let reverse_v6 = outbound_v6.clone().map(|sock| {
            tokio::spawn(udp_reverse_task(sock, inbound.clone(), locked_client.clone()))
        });

        // Per RFC 1928 §6: the UDP association is tied to this TCP control
        // connection. When the client closes it (or any read fails), tear down.
        let mut tcp_buf = [0u8; 64];
        loop {
            match control.read(&mut tcp_buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        info!(
            "SOCKS5 UDP ASSOCIATE control closed: {} (relay {})",
            client_tcp_addr, bnd_addr
        );

        forward.abort();
        if let Some(t) = reverse_v4 {
            t.abort();
        }
        if let Some(t) = reverse_v6 {
            t.abort();
        }

        if let (Some(ref stats), Some(ref conn_id)) = (&self.stats, &conn_id) {
            stats.close_connection(conn_id).await;
        }

        Ok(())
    }

    async fn send_udp_associate_response(
        &self,
        stream: &mut TcpStream,
        bnd_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut response = vec![SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0x00];
        match bnd_addr.ip() {
            IpAddr::V4(ip) => {
                response.push(SOCKS5_ATYP_IPV4);
                response.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                response.push(SOCKS5_ATYP_IPV6);
                response.extend_from_slice(&ip.octets());
            }
        }
        response.extend_from_slice(&bnd_addr.port().to_be_bytes());
        stream.write_all(&response).await?;
        Ok(())
    }

    async fn proxy_data(&self, client_stream: TcpStream, target_stream: TcpStream, client_addr: SocketAddr, _target_addr: String, stats: Option<Arc<StatsCollector>>, conn_id: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let (mut client_read, mut client_write) = client_stream.into_split();
        let (mut target_read, mut target_write) = target_stream.into_split();

        // Client→Target: copy then half-close target's write side so the
        // upstream sees FIN and can release any pending response.
        let client_to_target = async move {
            let n = tokio::io::copy(&mut client_read, &mut target_write).await?;
            let _ = target_write.shutdown().await;
            Ok::<u64, std::io::Error>(n)
        };

        // Target→Client: buffered via duplex pipe so reads from target
        // are decoupled from slow client writes. Shut down both the duplex
        // writer (so buf2c sees EOF) and the client write half (so the
        // client sees FIN) when each stage finishes.
        let buffer_size = self.buffer_size;
        let (mut duplex_w, mut duplex_r) = tokio::io::duplex(buffer_size);
        let t2buf = tokio::spawn(async move {
            let result = tokio::io::copy(&mut target_read, &mut duplex_w).await;
            let _ = duplex_w.shutdown().await;
            result
        });
        let buf2c = async move {
            let n = tokio::io::copy(&mut duplex_r, &mut client_write).await?;
            let _ = client_write.shutdown().await;
            Ok::<u64, std::io::Error>(n)
        };

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

struct Socks5UdpPacket<'a> {
    frag: u8,
    dst_addr: String,
    dst_port: u16,
    data: &'a [u8],
}

fn parse_socks5_udp_packet(buf: &[u8]) -> Option<Socks5UdpPacket<'_>> {
    // Minimum length: 2 RSV + 1 FRAG + 1 ATYP + 4 IPv4 + 2 port = 10
    if buf.len() < 10 {
        return None;
    }
    if buf[0] != 0 || buf[1] != 0 {
        return None;
    }
    let frag = buf[2];
    let atyp = buf[3];

    let (addr_str, addr_end) = match atyp {
        SOCKS5_ATYP_IPV4 => {
            if buf.len() < 4 + 4 + 2 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            (ip.to_string(), 4 + 4)
        }
        SOCKS5_ATYP_IPV6 => {
            if buf.len() < 4 + 16 + 2 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = Ipv6Addr::from(octets);
            (ip.to_string(), 4 + 16)
        }
        SOCKS5_ATYP_DOMAIN => {
            if buf.len() < 5 {
                return None;
            }
            let dlen = buf[4] as usize;
            if buf.len() < 5 + dlen + 2 {
                return None;
            }
            let s = std::str::from_utf8(&buf[5..5 + dlen]).ok()?.to_string();
            (s, 5 + dlen)
        }
        _ => return None,
    };

    let dst_port = u16::from_be_bytes([buf[addr_end], buf[addr_end + 1]]);
    let data = &buf[addr_end + 2..];
    Some(Socks5UdpPacket {
        frag,
        dst_addr: addr_str,
        dst_port,
        data,
    })
}

async fn udp_forward_task(
    inbound: Arc<UdpSocket>,
    outbound_v4: Option<Arc<UdpSocket>>,
    outbound_v6: Option<Arc<UdpSocket>>,
    locked_client: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = match inbound.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                debug!("UDP inbound recv error: {}", e);
                break;
            }
        };

        // Strict source filter: only accept from the announced address, or
        // (if none was announced) lock onto the first observed source.
        {
            let mut lock = locked_client.lock().await;
            match *lock {
                Some(expected) => {
                    if expected != src {
                        warn!(
                            "UDP relay dropping datagram from {} (expected {})",
                            src, expected
                        );
                        continue;
                    }
                }
                None => {
                    debug!("UDP relay locking onto first observed client: {}", src);
                    *lock = Some(src);
                }
            }
        }

        let pkt = match parse_socks5_udp_packet(&buf[..n]) {
            Some(p) => p,
            None => {
                debug!("UDP relay dropping malformed datagram from {}", src);
                continue;
            }
        };
        if pkt.frag != 0 {
            debug!(
                "UDP relay dropping fragmented datagram (FRAG={}) from {}",
                pkt.frag, src
            );
            continue;
        }

        let target_str = format!("{}:{}", pkt.dst_addr, pkt.dst_port);
        let target_sa = match crate::dns::resolve(&target_str).await {
            Ok(sa) => sa,
            Err(e) => {
                debug!("UDP relay DNS failure for {}: {}", target_str, e);
                continue;
            }
        };

        let outbound = match target_sa.ip() {
            IpAddr::V4(_) => outbound_v4.as_ref(),
            IpAddr::V6(_) => outbound_v6.as_ref(),
        };
        let Some(outbound) = outbound else {
            debug!(
                "UDP relay no outbound socket for address family of {}",
                target_sa
            );
            continue;
        };

        if let Err(e) = outbound.send_to(pkt.data, target_sa).await {
            debug!("UDP relay send_to {} failed: {}", target_sa, e);
        }
    }
}

async fn udp_reverse_task(
    outbound: Arc<UdpSocket>,
    inbound: Arc<UdpSocket>,
    locked_client: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = match outbound.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                debug!("UDP outbound recv error: {}", e);
                break;
            }
        };
        let client_addr = {
            let lock = locked_client.lock().await;
            match *lock {
                Some(a) => a,
                None => {
                    debug!(
                        "UDP reverse: no locked client yet, dropping reply from {}",
                        src
                    );
                    continue;
                }
            }
        };

        let mut out = Vec::with_capacity(n + 24);
        out.extend_from_slice(&[0x00, 0x00]); // RSV
        out.push(0x00);                       // FRAG
        match src.ip() {
            IpAddr::V4(ip) => {
                out.push(SOCKS5_ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(SOCKS5_ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&src.port().to_be_bytes());
        out.extend_from_slice(&buf[..n]);

        if let Err(e) = inbound.send_to(&out, client_addr).await {
            debug!("UDP reverse send_to client {} failed: {}", client_addr, e);
        }
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

    /// Regression test: when the upstream closes its side (sends FIN), the
    /// proxy must propagate that FIN to the client so the client's read
    /// returns 0 promptly. Before the half-close fix, this hung until TCP
    /// keepalive (~60s) and the test would time out.
    #[tokio::test]
    async fn test_socks5_propagates_upstream_fin() {
        tracing_subscriber::fmt::try_init().ok();

        // Upstream: accept one connection, write a payload, then close.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let payload: &[u8] = b"upstream-says-bye";
        tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            s.write_all(payload).await.unwrap();
            // Drop closes the socket and sends FIN.
        });

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
        sleep(Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&[SOCKS5_VERSION, 1, SOCKS5_NO_AUTH]).await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [SOCKS5_VERSION, SOCKS5_NO_AUTH]);

        let target_ip = match upstream_addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => panic!("Expected IPv4 address"),
        };
        let mut request = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_IPV4];
        request.extend_from_slice(&target_ip.octets());
        request.extend_from_slice(&upstream_addr.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut response = [0u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], SOCKS5_REP_SUCCESS);

        // read_to_end only returns once the proxy propagates EOF to us.
        // Cap with a short timeout — TCP keepalive is 60s, so a hang would
        // blow past this easily.
        let mut received = Vec::new();
        let read_result = tokio::time::timeout(
            Duration::from_secs(3),
            client.read_to_end(&mut received),
        )
        .await;

        assert!(
            read_result.is_ok(),
            "client.read_to_end did not return — proxy failed to propagate upstream FIN"
        );
        read_result.unwrap().unwrap();
        assert_eq!(received, payload);
    }

    /// Drive a real SOCKS5 UDP ASSOCIATE end-to-end:
    /// - Open the proxy
    /// - Bring up a UDP echo server as the "target"
    /// - Bind a client UDP socket and announce its addr in ASSOCIATE
    /// - Send a wrapped datagram, verify the echo comes back wrapped
    /// - Send a wrapped datagram from a *different* socket (wrong source) —
    ///   verify the proxy drops it (strict source filtering)
    #[tokio::test]
    async fn test_socks5_udp_associate_strict() {
        tracing_subscriber::fmt::try_init().ok();

        // Target: a UDP echo server.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, src) = match echo.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let _ = echo.send_to(&buf[..n], src).await;
            }
        });

        // Bring up the proxy.
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
        sleep(Duration::from_millis(50)).await;

        // Client UDP socket — we'll announce its addr in the ASSOCIATE.
        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_udp_addr = client_udp.local_addr().unwrap();
        let client_v4 = match client_udp_addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => panic!("expected v4"),
        };

        // Client TCP control connection: greet, then send ASSOCIATE.
        let mut control = TcpStream::connect(proxy_addr).await.unwrap();
        control
            .write_all(&[SOCKS5_VERSION, 1, SOCKS5_NO_AUTH])
            .await
            .unwrap();
        let mut buf = [0u8; 2];
        control.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [SOCKS5_VERSION, SOCKS5_NO_AUTH]);

        // ASSOCIATE with DST.ADDR = client_udp_addr (strict)
        let mut req = vec![
            SOCKS5_VERSION,
            SOCKS5_CMD_UDP_ASSOCIATE,
            0x00,
            SOCKS5_ATYP_IPV4,
        ];
        req.extend_from_slice(&client_v4.octets());
        req.extend_from_slice(&client_udp_addr.port().to_be_bytes());
        control.write_all(&req).await.unwrap();

        // Response: VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
        let mut resp = [0u8; 10];
        control.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], SOCKS5_VERSION);
        assert_eq!(resp[1], SOCKS5_REP_SUCCESS);
        assert_eq!(resp[3], SOCKS5_ATYP_IPV4);
        let bnd_ip = Ipv4Addr::new(resp[4], resp[5], resp[6], resp[7]);
        let bnd_port = u16::from_be_bytes([resp[8], resp[9]]);
        let relay_addr = SocketAddr::new(IpAddr::V4(bnd_ip), bnd_port);

        // Build a wrapped datagram targeting the echo server.
        let echo_v4 = match echo_addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => panic!("expected v4"),
        };
        let payload = b"ping-via-socks5-udp";
        let mut dg = vec![0x00, 0x00, 0x00, SOCKS5_ATYP_IPV4];
        dg.extend_from_slice(&echo_v4.octets());
        dg.extend_from_slice(&echo_addr.port().to_be_bytes());
        dg.extend_from_slice(payload);

        client_udp.send_to(&dg, relay_addr).await.unwrap();

        // Receive the wrapped echo reply.
        let mut rbuf = vec![0u8; 2048];
        let recv = tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut rbuf))
            .await
            .expect("relay never sent a reply")
            .unwrap();
        let n = recv.0;
        // Header: 2 RSV + 1 FRAG + 1 ATYP + 4 ADDR + 2 PORT = 10
        assert!(n >= 10 + payload.len());
        assert_eq!(&rbuf[0..3], &[0x00, 0x00, 0x00]);
        assert_eq!(rbuf[3], SOCKS5_ATYP_IPV4);
        let reply_ip = Ipv4Addr::new(rbuf[4], rbuf[5], rbuf[6], rbuf[7]);
        let reply_port = u16::from_be_bytes([rbuf[8], rbuf[9]]);
        assert_eq!(reply_ip, echo_v4);
        assert_eq!(reply_port, echo_addr.port());
        assert_eq!(&rbuf[10..n], payload);

        // Strict source filtering: a datagram from a *different* client socket
        // should be dropped. We verify by sending one and asserting no reply
        // arrives within a short window.
        let imposter = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        imposter.send_to(&dg, relay_addr).await.unwrap();
        let mut buf2 = vec![0u8; 2048];
        let timed = tokio::time::timeout(Duration::from_millis(400), imposter.recv_from(&mut buf2))
            .await;
        assert!(
            timed.is_err(),
            "imposter received a reply from the relay — strict source filter is broken"
        );

        // Closing the control TCP connection should tear down the relay.
        drop(control);
        sleep(Duration::from_millis(100)).await;
        // After teardown a fresh send_to from the original client should not
        // get echoed back (the relay socket is gone).
        client_udp.send_to(&dg, relay_addr).await.unwrap();
        let mut buf3 = vec![0u8; 2048];
        let after = tokio::time::timeout(
            Duration::from_millis(400),
            client_udp.recv_from(&mut buf3),
        )
        .await;
        assert!(
            after.is_err(),
            "relay still forwarding after control connection closed"
        );
    }
}