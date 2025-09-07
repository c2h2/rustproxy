use std::env;
use std::net::SocketAddr;
use tracing::{error, info};

mod tcp_proxy;
mod http_proxy;
mod socks5_proxy;
mod connection_cache;

#[cfg(test)]
mod test_utils;

use tcp_proxy::TcpProxy;
use http_proxy::HttpProxy;
use socks5_proxy::Socks5Proxy;
use connection_cache::parse_cache_size;

fn print_usage() {
    println!("Usage: rustproxy --listen <address:port> [--target <address:port>] --mode <tcp|http|socks5> [--cache-size <size>] [--socks5-auth <user:pass>]");
    println!("Options:");
    println!("  --listen <address:port>     Address to listen on");
    println!("  --target <address:port>     Address to proxy to (required for tcp mode only)");
    println!("  --mode <tcp|http|socks5>    Proxy mode");
    println!("  --cache-size <size>         Connection cache size (default: 256kb)");
    println!("                              Examples: 0, none, 256kb, 1mb, 8mb");
    println!("  --socks5-auth <user:pass>   SOCKS5 authentication (optional)");
    println!();
    println!("Examples:");
    println!("  rustproxy --listen 127.0.0.1:8080 --target 192.168.1.100:9000 --mode tcp --cache-size 1mb");
    println!("  rustproxy --listen 127.0.0.1:8080 --mode http");
    println!("  rustproxy --listen 127.0.0.1:1080 --mode socks5");
    println!("  rustproxy --listen 127.0.0.1:1080 --mode socks5 --socks5-auth user:password");
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
    
    if args.len() < 5 || args.len() > 11 {
        print_usage();
        std::process::exit(1);
    }

    let mut listen_addr = None;
    let mut target_addr = None;
    let mut mode = None;
    let mut cache_size = None;
    let mut socks5_auth = None;

    for i in (1..args.len()).step_by(2) {
        match args[i].as_str() {
            "--listen" => {
                if i + 1 < args.len() {
                    listen_addr = Some(args[i + 1].clone());
                }
            }
            "--target" => {
                if i + 1 < args.len() {
                    target_addr = Some(args[i + 1].clone());
                }
            }
            "--mode" => {
                if i + 1 < args.len() {
                    mode = Some(args[i + 1].clone());
                }
            }
            "--cache-size" => {
                if i + 1 < args.len() {
                    cache_size = Some(args[i + 1].clone());
                }
            }
            "--socks5-auth" => {
                if i + 1 < args.len() {
                    socks5_auth = Some(args[i + 1].clone());
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
            let proxy = TcpProxy::new(&listen, &target, cache_size_bytes);
            if let Err(e) = proxy.start().await {
                error!("TCP proxy error: {}", e);
                return Err(e);
            }
        }
        "http" => {
            let target = target.unwrap_or_else(|| "".to_string());
            let proxy = HttpProxy::new(&listen, &target, cache_size_bytes);
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
                Socks5Proxy::with_auth(&listen, cache_size_bytes, parts[0].to_string(), parts[1].to_string())
            } else {
                Socks5Proxy::new(&listen, cache_size_bytes)
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