use std::env;
use std::net::SocketAddr;
use tracing::{error, info};

mod tcp_proxy;
mod http_proxy;
mod socks5_proxy;
mod connection_cache;
pub mod stats;
pub mod manager;

#[cfg(test)]
mod test_utils;

use tcp_proxy::TcpProxy;
use http_proxy::HttpProxy;
use socks5_proxy::Socks5Proxy;
use connection_cache::parse_cache_size;

fn print_usage() {
    println!("Usage:");
    println!("  rustproxy --manager [--listen <address:port>]");
    println!("  rustproxy --listen <address:port> [--target <address:port>] --mode <tcp|http|socks5> [options]");
    println!();
    println!("Manager Mode:");
    println!("  --manager                    Start in manager mode (default: 127.0.0.1:13337)");
    println!("  --listen <address:port>      Manager HTTP interface address");
    println!();
    println!("Proxy Mode Options:");
    println!("  --listen <address:port>      Address to listen on");
    println!("  --target <address:port>      Address to proxy to (required for tcp mode only)");
    println!("  --mode <tcp|http|socks5>     Proxy mode");
    println!("  --cache-size <size>          Connection cache size (default: 256kb)");
    println!("                               Examples: 0, none, 256kb, 1mb, 8mb");
    println!("  --socks5-auth <user:pass>    SOCKS5 authentication (optional)");
    println!("  --manager-addr <addr:port>   Manager address for stats reporting");
    println!();
    println!("Examples:");
    println!("  rustproxy --manager");
    println!("  rustproxy --manager --listen 0.0.0.0:13337");
    println!("  rustproxy --listen 127.0.0.1:8080 --target 192.168.1.100:9000 --mode tcp --manager-addr 127.0.0.1:14337");
    println!("  rustproxy --listen 127.0.0.1:8080 --mode http");
    println!("  rustproxy --listen 127.0.0.1:1080 --mode socks5 --socks5-auth user:password");
    println!();
    println!("Environment Variables:");
    println!("  RUSTPROXY_MANAGER=<addr:port>  Set manager address for stats reporting");
}

fn validate_no_self_connection(listen: &str, target: &str) -> Result<(), String> {
    let listen_addr: SocketAddr = listen.parse()
        .map_err(|_| format!("Invalid listen address: {}", listen))?;
    let target_addr: SocketAddr = target.parse()
        .map_err(|_| format!("Invalid target address: {}", target))?;
    
    if listen_addr == target_addr {
        return Err("Listen and target addresses cannot be the same (self-connection not allowed)".to_string());
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    // Check for manager mode first
    if args.contains(&"--manager".to_string()) {
        let mut listen_addr = "127.0.0.1:13337".to_string();
        
        for i in 1..args.len() {
            if args[i] == "--listen" && i + 1 < args.len() {
                listen_addr = args[i + 1].clone();
            }
        }
        
        info!("Starting RustProxy Manager on {}", listen_addr);
        let manager = manager::Manager::new(&listen_addr);
        return manager.start().await;
    }

    // Parse proxy mode arguments
    let mut listen_addr = None;
    let mut target_addr = None;
    let mut mode = None;
    let mut cache_size = None;
    let mut socks5_auth = None;
    let mut manager_addr = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                if i + 1 < args.len() {
                    listen_addr = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--target" => {
                if i + 1 < args.len() {
                    target_addr = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--mode" => {
                if i + 1 < args.len() {
                    mode = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--cache-size" => {
                if i + 1 < args.len() {
                    cache_size = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--socks5-auth" => {
                if i + 1 < args.len() {
                    socks5_auth = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--manager-addr" => {
                if i + 1 < args.len() {
                    manager_addr = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
    }

    let listen = listen_addr.ok_or("Missing --listen parameter")?;
    let mode = mode.ok_or("Missing --mode parameter")?;
    
    // Target is only required for tcp mode
    let target = if mode == "tcp" {
        Some(target_addr.ok_or("Missing --target parameter for tcp mode")?)
    } else {
        target_addr
    };

    // Default to 256KB cache if not specified
    let cache_size_str = cache_size.unwrap_or_else(|| "256kb".to_string());
    let cache_size_bytes = match parse_cache_size(&cache_size_str) {
        Ok(size) => size,
        Err(e) => {
            eprintln!("Error parsing cache size: {}", e);
            std::process::exit(1);
        }
    };

    if mode != "tcp" && mode != "http" && mode != "socks5" {
        eprintln!("Mode must be 'tcp', 'http', or 'socks5'");
        std::process::exit(1);
    }

    // Validate no self-connection for tcp mode
    if mode == "tcp" {
        if let Some(ref target_addr) = target {
            if let Err(e) = validate_no_self_connection(&listen, target_addr) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Get manager address from command line or environment variable
    let manager_socket_addr = manager_addr
        .or_else(|| env::var("RUSTPROXY_MANAGER").ok())
        .and_then(|addr| {
            addr.parse::<SocketAddr>().ok().map(|mut socket_addr| {
                // Manager UDP port is 1000 above HTTP port
                socket_addr.set_port(socket_addr.port() + 1000);
                socket_addr
            })
        });

    if let Some(addr) = &manager_socket_addr {
        info!("Stats reporting enabled to manager at {}", addr);
    }

    let cache_display = if cache_size_bytes == 0 {
        "disabled".to_string()
    } else if cache_size_bytes >= 1024 * 1024 {
        format!("{}MB", cache_size_bytes / (1024 * 1024))
    } else {
        format!("{}KB", cache_size_bytes / 1024)
    };

    match mode.as_str() {
        "socks5" => {
            info!("Starting SOCKS5 proxy on {} (cache: {})", listen, cache_display);
        }
        "tcp" => {
            info!("Starting {} proxy: {} -> {} (cache: {})", mode, listen, target.as_ref().unwrap(), cache_display);
        }
        "http" => {
            info!("Starting {} proxy on {} (cache: {})", mode, listen, cache_display);
        }
        _ => unreachable!(),
    }

    match mode.as_str() {
        "tcp" => {
            let target = target.unwrap();
            let proxy = TcpProxy::with_stats(&listen, &target, cache_size_bytes, manager_socket_addr);
            if let Err(e) = proxy.start().await {
                error!("TCP proxy error: {}", e);
                return Err(e);
            }
        }
        "http" => {
            let target = target.unwrap_or_else(|| "".to_string());
            let proxy = HttpProxy::with_stats(&listen, &target, cache_size_bytes, manager_socket_addr);
            if let Err(e) = proxy.start().await {
                error!("HTTP proxy error: {}", e);
                return Err(e);
            }
        }
        "socks5" => {
            let proxy = if let Some(auth_str) = socks5_auth {
                let parts: Vec<&str> = auth_str.split(':').collect();
                if parts.len() != 2 {
                    eprintln!("SOCKS5 auth must be in format 'username:password'");
                    std::process::exit(1);
                }
                Socks5Proxy::with_auth_and_stats(&listen, cache_size_bytes, parts[0].to_string(), parts[1].to_string(), manager_socket_addr)
            } else {
                Socks5Proxy::with_stats(&listen, cache_size_bytes, manager_socket_addr)
            };
            
            if let Err(e) = proxy.start().await {
                error!("SOCKS5 proxy error: {}", e);
                return Err(e);
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}