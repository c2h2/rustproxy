use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
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
        // Keep the client TCP leg warm before/during the long-lived tunnel.
        crate::tcp_proxy::tune_tcp_stream(stream.get_ref());

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
        let target_stream = match crate::dns::tcp_connect(&target_str).await {
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
        // buffer_size is retained for CLI/config compatibility; the shared
        // relay uses socket buffers for backpressure instead of a duplex pipe.
        let _ = self.buffer_size;

        // Keep the target leg warm through NATs and detect dead peers.
        // (Client side is an SS-encrypted stream, not a plain TcpStream.)
        crate::tcp_proxy::tune_tcp_stream(&target_stream);

        // Independent per-direction pumps with a bounded teardown grace.
        // The previous tokio::join! both (a) leaked the task and both sockets
        // when a client vanished while the target stayed idle, and (b) never
        // shut down the target's write side, so a client half-close (FIN) was
        // never propagated and FIN-terminated request protocols would hang.
        // run_pumps fixes both: it half-closes the peer on EOF and tears the
        // relay down once a broken direction's drain grace expires.
        let (bytes_to_target, bytes_to_client, e_c2s, e_s2c) =
            crate::tcp_proxy::run_pumps(client_stream, target_stream).await;

        if let Some(e) = e_c2s {
            debug!("SS client->target ended after {} bytes for {}: {}", bytes_to_target, client_addr, e);
        }
        if let Some(e) = e_s2c {
            debug!("SS target->client ended after {} bytes for {}: {}", bytes_to_client, client_addr, e);
        }

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
