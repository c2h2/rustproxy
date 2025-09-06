#[cfg(test)]
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::info;

pub struct MockTcpServer {
    listener: TcpListener,
    addr: SocketAddr,
}

impl MockTcpServer {
    pub async fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        Ok(Self { listener, addr })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn echo_server(self) {
        while let Ok((mut socket, addr)) = self.listener.accept().await {
            info!("Mock server accepted connection from {}", addr);
            
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[0..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }

    pub async fn fixed_response_server(self, response: String) {
        while let Ok((mut socket, addr)) = self.listener.accept().await {
            info!("Mock server accepted connection from {}", addr);
            let response = response.clone();
            
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                if socket.read(&mut buf).await.is_ok() {
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            });
        }
    }

    pub async fn http_server(self) {
        while let Ok((mut socket, addr)) = self.listener.accept().await {
            info!("Mock HTTP server accepted connection from {}", addr);
            
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                if let Ok(n) = socket.read(&mut buf).await {
                    let request = String::from_utf8_lossy(&buf[0..n]);
                    info!("Received HTTP request: {}", request);
                    
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            });
        }
    }
}