use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub struct TcpProxy {
    bind_addr: String,
    target_addr: String,
}

impl TcpProxy {
    pub fn new(bind_addr: &str, target_addr: &str) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            target_addr: target_addr.to_string(),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        info!("TCP proxy listening on {} -> {}", self.bind_addr, self.target_addr);

        loop {
            let (inbound, client_addr) = listener.accept().await?;
            let target_addr = self.target_addr.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(inbound, client_addr, target_addr).await {
                    error!("Error handling connection from {}: {}", client_addr, e);
                }
            });
        }
    }

    pub async fn handle_connection(
        mut inbound: TcpStream,
        client_addr: SocketAddr,
        target_addr: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut outbound = TcpStream::connect(&target_addr).await?;
        info!("Proxying connection from {} to {}", client_addr, target_addr);

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
                error!("Error in bidirectional copy for {}: {}", client_addr, e);
            }
        }

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

        let proxy = TcpProxy::new("127.0.0.1:0", &target_addr.to_string());
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((inbound, client_addr)) = proxy_listener.accept().await {
                let target_addr = target_addr.to_string();
                tokio::spawn(async move {
                    let _ = TcpProxy::handle_connection(inbound, client_addr, target_addr).await;
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
                    let _ = TcpProxy::handle_connection(inbound, client_addr, target_addr).await;
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
                    let _ = TcpProxy::handle_connection(inbound, client_addr, target_addr).await;
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