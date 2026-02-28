//! TCP benchmark server — accepts connections and exercises both directions.
//!
//! Usage:
//!   cargo run --release --example tcp_bench_server -- --listen 0.0.0.0:9000 [--size 512]
//!
//! Protocol (per connection):
//!   1. Server reads all data from client until client shuts down write half (upload / sink).
//!   2. Server sends `size` MiB of data back, then shuts down (download / source).
//!   3. Server prints throughput for both directions.

use std::env;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DEFAULT_SIZE_MIB: usize = 512;
const CHUNK: usize = 256 * 1024; // 256 KiB write chunks

fn parse_args() -> (String, usize) {
    let args: Vec<String> = env::args().collect();
    let mut listen = "0.0.0.0:9000".to_string();
    let mut size_mib = DEFAULT_SIZE_MIB;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" | "-l" => {
                i += 1;
                listen = args[i].clone();
            }
            "--size" | "-s" => {
                i += 1;
                size_mib = args[i].parse().expect("invalid --size");
            }
            "--help" | "-h" => {
                println!("tcp_bench_server — sink + source benchmark server");
                println!();
                println!("  --listen <addr:port>   Listen address (default: 0.0.0.0:9000)");
                println!("  --size <MiB>           Data to send back per connection (default: 512)");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown flag: {}", other);
                std::process::exit(1);
            }
        }
        i += 1;
    }
    (listen, size_mib)
}

#[tokio::main]
async fn main() {
    let (listen, size_mib) = parse_args();
    let total_send = size_mib as u64 * 1024 * 1024;

    let listener = TcpListener::bind(&listen).await.expect("bind failed");
    println!("[server] Listening on {}", listen);
    println!("[server] Will send {} MiB per connection after receiving upload", size_mib);

    loop {
        let (mut stream, peer) = listener.accept().await.expect("accept failed");
        let _ = stream.set_nodelay(true);

        tokio::spawn(async move {
            println!("[server] Connection from {}", peer);

            // --- Phase 1: Sink (receive upload) ---
            let t0 = Instant::now();
            let mut rx_total: u64 = 0;
            let mut buf = vec![0u8; CHUNK];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => rx_total += n as u64,
                    Err(e) => {
                        eprintln!("[server] Read error from {}: {}", peer, e);
                        return;
                    }
                }
            }
            let rx_dur = t0.elapsed();
            let rx_mbps = if rx_dur.as_secs_f64() > 0.0 {
                (rx_total as f64 / 1_000_000.0) / rx_dur.as_secs_f64()
            } else {
                0.0
            };
            println!(
                "[server] RX from {}: {:.2} MiB in {:.3}s = {:.1} MB/s",
                peer,
                rx_total as f64 / (1024.0 * 1024.0),
                rx_dur.as_secs_f64(),
                rx_mbps
            );

            // --- Phase 2: Source (send download data) ---
            let t1 = Instant::now();
            let data = vec![0xABu8; CHUNK];
            let mut tx_total: u64 = 0;
            while tx_total < total_send {
                let remain = (total_send - tx_total) as usize;
                let n = remain.min(CHUNK);
                match stream.write_all(&data[..n]).await {
                    Ok(()) => tx_total += n as u64,
                    Err(e) => {
                        eprintln!("[server] Write error to {}: {}", peer, e);
                        return;
                    }
                }
            }
            let _ = stream.shutdown().await;
            let tx_dur = t1.elapsed();
            let tx_mbps = if tx_dur.as_secs_f64() > 0.0 {
                (tx_total as f64 / 1_000_000.0) / tx_dur.as_secs_f64()
            } else {
                0.0
            };
            println!(
                "[server] TX to   {}: {:.2} MiB in {:.3}s = {:.1} MB/s",
                peer,
                tx_total as f64 / (1024.0 * 1024.0),
                tx_dur.as_secs_f64(),
                tx_mbps
            );
        });
    }
}
