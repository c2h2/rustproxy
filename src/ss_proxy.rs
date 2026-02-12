use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tracing::{info, debug, warn};

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::tcprelay::proxy_listener::ProxyListener;

use crate::stats::StatsCollector;

#[derive(Clone)]
pub struct SsProxy {
    bind_addr: String,
    password: String,
    method: CipherKind,
    stats: Option<Arc<StatsCollector>>,
    buffer_size: usize,
}

impl SsProxy {
    pub fn with_stats(
        bind_addr: &str,
        password: String,
        method: CipherKind,
        manager_addr: Option<SocketAddr>,
        buffer_size: usize,
    ) -> Self {
        let stats = manager_addr.map(|addr| {
            Arc::new(StatsCollector::new("ss", bind_addr, Some(addr)))
        });

        Self {
            bind_addr: bind_addr.to_string(),
            password,
            method,
            stats,
            buffer_size,
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let context = Context::new_shared(ServerType::Server);

        let svr_cfg = ServerConfig::new(
            self.bind_addr.parse::<SocketAddr>()?,
            &self.password,
            self.method,
        )?;

        let listener = ProxyListener::bind(context, &svr_cfg).await?;

        info!(
            "Shadowsocks proxy listening on {} (method: {:?})",
            self.bind_addr, self.method
        );

        // Start stats reporting if enabled
        if let Some(ref stats) = self.stats {
            stats.clone().start_reporting().await;
        }

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let proxy = self.clone();

            tokio::spawn(async move {
                if let Err(e) = proxy.handle_connection(stream, peer_addr).await {
                    debug!("SS connection from {} ended: {}", peer_addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        &self,
        mut stream: shadowsocks::relay::tcprelay::proxy_stream::server::ProxyServerStream<TcpStream>,
        peer_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Handshake: decrypt first payload, extract target address
        let target_addr = stream.handshake().await?;
        let target_str = target_addr.to_string();

        debug!("SS CONNECT from {} to {}", peer_addr, target_str);

        // Track connection in stats
        let conn_id = if let Some(ref stats) = self.stats {
            Some(stats.new_connection(peer_addr, target_str.clone()).await)
        } else {
            None
        };

        // Connect to the real target
        let target_stream = match TcpStream::connect(&target_str).await {
            Ok(s) => s,
            Err(e) => {
                warn!("SS failed to connect to {}: {}", target_str, e);
                if let (Some(ref stats), Some(ref cid)) = (&self.stats, &conn_id) {
                    stats.close_connection(cid).await;
                }
                return Err(e.into());
            }
        };

        info!("SS connection established: {} -> {}", peer_addr, target_str);

        // Relay data bidirectionally
        self.proxy_data(stream, target_stream, peer_addr, target_str, self.stats.clone(), conn_id)
            .await
    }

    async fn proxy_data(
        &self,
        client_stream: shadowsocks::relay::tcprelay::proxy_stream::server::ProxyServerStream<TcpStream>,
        target_stream: TcpStream,
        client_addr: SocketAddr,
        _target_addr: String,
        stats: Option<Arc<StatsCollector>>,
        conn_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut target_read, mut target_write) = target_stream.into_split();

        // Client -> Target: direct copy
        let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);

        // Target -> Client: buffered via duplex pipe
        let buffer_size = self.buffer_size;
        let (mut duplex_w, mut duplex_r) = tokio::io::duplex(buffer_size);
        let t2buf = tokio::spawn(async move {
            let result = tokio::io::copy(&mut target_read, &mut duplex_w).await;
            let _ = duplex_w.shutdown().await;
            result
        });
        let buf2c = tokio::io::copy(&mut duplex_r, &mut client_write);

        let (result1, r_t2buf, r_buf2c) = tokio::join!(client_to_target, t2buf, buf2c);

        let bytes_to_target = match &result1 {
            Ok(bytes) => *bytes,
            Err(e) => {
                debug!("SS client->target error for {}: {}", client_addr, e);
                0
            }
        };
        if let Err(e) = &r_t2buf {
            debug!("SS target->buffer task error for {}: {}", client_addr, e);
        } else if let Ok(Err(e)) = &r_t2buf {
            debug!("SS target->buffer copy error for {}: {}", client_addr, e);
        }
        let bytes_to_client = match &r_buf2c {
            Ok(bytes) => *bytes,
            Err(e) => {
                debug!("SS buffer->client error for {}: {}", client_addr, e);
                0
            }
        };

        info!(
            "SS connection {} closed. TX {} bytes, RX {} bytes",
            client_addr, bytes_to_target, bytes_to_client
        );

        if let (Some(ref stats), Some(ref cid)) = (&stats, &conn_id) {
            stats.update_connection(cid, bytes_to_target, bytes_to_client).await;
            stats.close_connection(cid).await;
        }

        Ok(())
    }
}
