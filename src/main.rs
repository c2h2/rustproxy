use std::env;
use std::net::SocketAddr;
use tracing::{error, info};

mod tcp_proxy;
mod http_proxy;

#[cfg(test)]
mod test_utils;

use tcp_proxy::TcpProxy;
use http_proxy::HttpProxy;

fn print_usage() {
    println!("Usage: rustproxy --listen <address:port> --target <address:port> --mode <tcp|http>");
    println!("Example: rustproxy --listen 127.0.0.1:8080 --target 192.168.1.100:9000 --mode tcp");
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
    
    if args.len() != 7 {
        print_usage();
        std::process::exit(1);
    }

    let mut listen_addr = None;
    let mut target_addr = None;
    let mut mode = None;

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
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
    }

    let listen = listen_addr.ok_or("Missing --listen parameter")?;
    let target = target_addr.ok_or("Missing --target parameter")?;
    let mode = mode.ok_or("Missing --mode parameter")?;

    if mode != "tcp" && mode != "http" {
        eprintln!("Mode must be either 'tcp' or 'http'");
        std::process::exit(1);
    }

    if let Err(e) = validate_no_self_connection(&listen, &target) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    info!("Starting {} proxy: {} -> {}", mode, listen, target);

    match mode.as_str() {
        "tcp" => {
            let proxy = TcpProxy::new(&listen, &target);
            if let Err(e) = proxy.start().await {
                error!("TCP proxy error: {}", e);
                return Err(e);
            }
        }
        "http" => {
            let proxy = HttpProxy::new(&listen, &target);
            if let Err(e) = proxy.start().await {
                error!("HTTP proxy error: {}", e);
                return Err(e);
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}