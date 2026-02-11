use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

mod tcp_proxy;
mod http_proxy;
mod socks5_proxy;
mod connection_cache;
pub mod stats;
pub mod manager;
mod lb;
mod web;
mod healthcheck;
mod traffic_log;

#[cfg(test)]
mod test_utils;

use tcp_proxy::TcpProxy;
use http_proxy::HttpProxy;
use socks5_proxy::Socks5Proxy;
use connection_cache::parse_cache_size;
use lb::LbAlgorithm;

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
    println!("                               Comma-separated for load balancing (tcp mode)");
    println!("  --mode <tcp|http|socks5>     Proxy mode");
    println!("  --cache-size <size>          Connection cache size (default: 64mb)");
    println!("                               Examples: 0, none, 256kb, 1mb, 8mb");
    println!("  --socks5-auth <user:pass>    SOCKS5 authentication (optional)");
    println!("  --manager-addr <addr:port>   Manager address for stats reporting");
    println!("  --lb <random|roundrobin>     Load balancing algorithm (tcp mode, requires multiple targets)");
    println!("  --http-interface <addr:port>  HTTP dashboard for LB stats (e.g. :8888)");
    println!("  --traffic-log <path>         CSV file for persistent traffic history (default: ./rustproxy_traffic.csv)");
    println!("  --buffer-size <size>          Server→client relay buffer (default: 16mb)");
    println!("                               Decouples fast server reads from slow client writes");
    println!("                               Examples: 256kb, 16mb, 64mb");
    println!("  --healthcheck                Enable SOCKS5 healthcheck for TCP LB backends");
    println!("                               Probes each backend via SOCKS5 CONNECT every 60s");
    println!("                               Disables failing backends; re-enables on recovery");
    println!("                               Safety valve: re-enables all if every backend fails");
    println!();
    println!("Examples:");
    println!("  rustproxy --manager");
    println!("  rustproxy --manager --listen 0.0.0.0:13337");
    println!("  rustproxy --listen 127.0.0.1:8080 --target 192.168.1.100:9000 --mode tcp --manager-addr 127.0.0.1:14337");
    println!("  rustproxy --listen 127.0.0.1:8080 --mode http");
    println!("  rustproxy --listen 127.0.0.1:1080 --mode socks5 --socks5-auth user:password");
    println!();
    println!("Load Balancing Example:");
    println!("  rustproxy --listen 127.0.0.1:8080 \\");
    println!("    --target 192.168.1.100:9000,192.168.1.100:9001,192.168.1.100:9002 \\");
    println!("    --mode tcp --lb random --http-interface :8888");
    println!();
    println!("Load Balancing with Healthcheck:");
    println!("  rustproxy --listen 127.0.0.1:8080 \\");
    println!("    --target 10.0.0.1:1080,10.0.0.2:1080,10.0.0.3:1080 \\");
    println!("    --mode tcp --lb roundrobin --http-interface :8888 --healthcheck");
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

/// Normalize bind addresses: `:8888` → `0.0.0.0:8888`
fn normalize_bind_addr(addr: &str) -> String {
    if addr.starts_with(':') {
        format!("0.0.0.0{}", addr)
    } else {
        addr.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Raise fd soft limit to hard limit and compute max connections
    let max_connections = {
        let old_soft = rlimit::getrlimit(rlimit::Resource::NOFILE)
            .map(|(soft, _)| soft)
            .unwrap_or(1024);
        let new_soft = rlimit::increase_nofile_limit(u64::MAX).unwrap_or(old_soft);
        info!("fd limit: {} -> {} (soft raised to hard)", old_soft, new_soft);
        let max_conns = ((new_soft / 2) as usize).saturating_sub(100);
        let max_conns = max_conns.max(128); // floor at 128
        info!("Max connections: {} (derived from fd limit {})", max_conns, new_soft);
        max_conns
    };

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
    let mut lb_algorithm = None;
    let mut http_interface = None;
    let mut healthcheck_enabled = false;
    let mut traffic_log_path = String::from("./rustproxy_traffic.csv");
    let mut buffer_size_str = None;

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
            "--lb" => {
                if i + 1 < args.len() {
                    lb_algorithm = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--http-interface" => {
                if i + 1 < args.len() {
                    http_interface = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--traffic-log" => {
                if i + 1 < args.len() {
                    traffic_log_path = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--buffer-size" => {
                if i + 1 < args.len() {
                    buffer_size_str = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--healthcheck" => {
                healthcheck_enabled = true;
                i += 1;
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
    let cache_size_str = cache_size.unwrap_or_else(|| "64mb".to_string());
    let cache_size_bytes = match parse_cache_size(&cache_size_str) {
        Ok(size) => size,
        Err(e) => {
            eprintln!("Error parsing cache size: {}", e);
            std::process::exit(1);
        }
    };

    let buffer_size_val = buffer_size_str.unwrap_or_else(|| "16mb".to_string());
    let buffer_size_bytes = match parse_cache_size(&buffer_size_val) {
        Ok(size) => size,
        Err(e) => {
            eprintln!("Error parsing buffer size: {}", e);
            std::process::exit(1);
        }
    };

    if mode != "tcp" && mode != "http" && mode != "socks5" {
        eprintln!("Mode must be 'tcp', 'http', or 'socks5'");
        std::process::exit(1);
    }

    // Validate --lb and --http-interface are only used with tcp mode
    if mode != "tcp" && lb_algorithm.is_some() {
        eprintln!("--lb is only valid with --mode tcp");
        std::process::exit(1);
    }
    if mode != "tcp" && http_interface.is_some() {
        eprintln!("--http-interface is only valid with --mode tcp");
        std::process::exit(1);
    }
    if mode != "tcp" && healthcheck_enabled {
        eprintln!("--healthcheck is only valid with --mode tcp");
        std::process::exit(1);
    }

    // Validate no self-connection for tcp mode (single target only)
    if mode == "tcp" {
        if let Some(ref target_addr) = target {
            if !target_addr.contains(',') {
                if let Err(e) = validate_no_self_connection(&listen, target_addr) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
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

            // Determine if we're in load-balancing mode
            let is_lb_mode = target.contains(',') || lb_algorithm.is_some();

            if is_lb_mode {
                // Parse LB algorithm (default: random)
                let algo = match &lb_algorithm {
                    Some(s) => match LbAlgorithm::from_str(s) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        }
                    },
                    None => LbAlgorithm::Random,
                };

                let lb = match lb::LoadBalancer::new(&target, algo) {
                    Ok(lb) => Arc::new(lb),
                    Err(e) => {
                        eprintln!("Error creating load balancer: {}", e);
                        std::process::exit(1);
                    }
                };

                let proxy = TcpProxy::with_lb(&listen, lb.clone(), cache_size_bytes, manager_socket_addr, max_connections, buffer_size_bytes);

                // Load persistent traffic log
                let tlog = Arc::new(traffic_log::TrafficLog::load(std::path::Path::new(&traffic_log_path)));

                // Spawn web interface if configured
                if let Some(ref iface) = http_interface {
                    let web_bind = normalize_bind_addr(iface);
                    let web_state = Arc::new(web::WebState {
                        lb: lb.clone(),
                        listen_addr: listen.clone(),
                        active_connections: proxy.active_connections_ref(),
                        total_tx_bytes: proxy.total_tx_ref(),
                        total_rx_bytes: proxy.total_rx_ref(),
                        start_time: proxy.start_time(),
                        max_connections: proxy.max_connections(),
                        traffic_log: tlog.clone(),
                    });
                    tokio::spawn(web::start_web_interface(web_bind, web_state));
                }

                // Spawn background traffic recorder (every 60s)
                traffic_log::spawn_traffic_recorder(
                    tlog.clone(),
                    proxy.total_tx_ref(),
                    proxy.total_rx_ref(),
                );

                // Spawn self-test task
                {
                    let proxy_addr = listen.clone();
                    let backends: Vec<SocketAddr> = lb.backends().iter().map(|b| b.addr).collect();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        self_test(&proxy_addr, &backends).await;
                    });
                }

                // Spawn SOCKS5 healthcheck if enabled
                if healthcheck_enabled {
                    info!("SOCKS5 healthcheck enabled for {} backends", lb.backends().len());
                    healthcheck::spawn_healthcheck_task(lb.clone());
                }

                if let Err(e) = proxy.start().await {
                    error!("TCP LB proxy error: {}", e);
                    return Err(e);
                }
            } else {
                // Single-target mode (unchanged)
                let proxy = TcpProxy::with_stats(&listen, &target, cache_size_bytes, manager_socket_addr, max_connections, buffer_size_bytes);
                if let Err(e) = proxy.start().await {
                    error!("TCP proxy error: {}", e);
                    return Err(e);
                }
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
                Socks5Proxy::with_auth_and_stats(&listen, cache_size_bytes, parts[0].to_string(), parts[1].to_string(), manager_socket_addr, buffer_size_bytes)
            } else {
                Socks5Proxy::with_stats(&listen, cache_size_bytes, manager_socket_addr, buffer_size_bytes)
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

/// Non-fatal self-test: try connecting to proxy and each backend after startup.
async fn self_test(proxy_addr: &str, backends: &[SocketAddr]) {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    // Test proxy listener
    match timeout(Duration::from_secs(5), TcpStream::connect(proxy_addr)).await {
        Ok(Ok(_)) => info!("[self-test] PASS: proxy listener {} is reachable", proxy_addr),
        Ok(Err(e)) => warn!("[self-test] FAIL: cannot connect to proxy {}: {}", proxy_addr, e),
        Err(_) => warn!("[self-test] FAIL: timeout connecting to proxy {}", proxy_addr),
    }

    // Test each backend
    for addr in backends {
        match timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => info!("[self-test] PASS: backend {} is reachable", addr),
            Ok(Err(e)) => warn!("[self-test] WARN: backend {} unreachable: {}", addr, e),
            Err(_) => warn!("[self-test] WARN: timeout connecting to backend {}", addr),
        }
    }
}
