//! TCP benchmark client — connects and exercises both directions.
//!
//! Usage:
//!   cargo run --release --example tcp_bench_client -- --connect 127.0.0.1:9000 [--size 512]
//!
//! Protocol (matches tcp_bench_server):
//!   1. Client sends `size` MiB of data, then shuts down write half (upload test).
//!   2. Client reads all data from server until EOF (download test).
//!   3. Client prints throughput for both directions.

use std::env;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_SIZE_MIB: usize = 512;
const CHUNK: usize = 256 * 1024; // 256 KiB write chunks

fn parse_args() -> (String, usize) {
    let args: Vec<String> = env::args().collect();
    let mut connect = "127.0.0.1:9000".to_string();
    let mut size_mib = DEFAULT_SIZE_MIB;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--connect" | "-c" => {
                i += 1;
                connect = args[i].clone();
            }
            "--size" | "-s" => {
                i += 1;
                size_mib = args[i].parse().expect("invalid --size");
            }
            "--help" | "-h" => {
                println!("tcp_bench_client — upload + download benchmark client");
                println!();
                println!("  --connect <addr:port>  Server address (default: 127.0.0.1:9000)");
                println!("  --size <MiB>           Data to send (default: 512)");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown flag: {}", other);
                std::process::exit(1);
            }
        }
        i += 1;
    }
    (connect, size_mib)
}

#[tokio::main]
async fn main() {
    let (connect, size_mib) = parse_args();
    let total_send = size_mib as u64 * 1024 * 1024;

    println!("[client] Connecting to {} ...", connect);
    let mut stream = TcpStream::connect(&connect).await.expect("connect failed");
    let _ = stream.set_nodelay(true);
    println!("[client] Connected. Upload {} MiB, then receive download.", size_mib);

    // --- Phase 1: Upload ---
    let t0 = Instant::now();
    let data = vec![0xCDu8; CHUNK];
    let mut tx_total: u64 = 0;
    while tx_total < total_send {
        let remain = (total_send - tx_total) as usize;
        let n = remain.min(CHUNK);
        match stream.write_all(&data[..n]).await {
            Ok(()) => tx_total += n as u64,
            Err(e) => {
                eprintln!("[client] Upload write error: {}", e);
                return;
            }
        }
    }
    // Shut down write half so server sees EOF
    stream.shutdown().await.expect("shutdown failed");
    let tx_dur = t0.elapsed();
    let tx_mbps = if tx_dur.as_secs_f64() > 0.0 {
        (tx_total as f64 / 1_000_000.0) / tx_dur.as_secs_f64()
    } else {
        0.0
    };
    println!(
        "[client] UPLOAD:   {:.2} MiB in {:.3}s = {:.1} MB/s",
        tx_total as f64 / (1024.0 * 1024.0),
        tx_dur.as_secs_f64(),
        tx_mbps
    );

    // --- Phase 2: Download ---
    let t1 = Instant::now();
    let mut rx_total: u64 = 0;
    let mut buf = vec![0u8; CHUNK];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => rx_total += n as u64,
            Err(e) => {
                eprintln!("[client] Download read error: {}", e);
                return;
            }
        }
    }
    let rx_dur = t1.elapsed();
    let rx_mbps = if rx_dur.as_secs_f64() > 0.0 {
        (rx_total as f64 / 1_000_000.0) / rx_dur.as_secs_f64()
    } else {
        0.0
    };
    println!(
        "[client] DOWNLOAD: {:.2} MiB in {:.3}s = {:.1} MB/s",
        rx_total as f64 / (1024.0 * 1024.0),
        rx_dur.as_secs_f64(),
        rx_mbps
    );

    // --- Summary ---
    println!();
    println!("[client] Summary:");
    println!("  Upload:   {:.1} MB/s  ({:.2} MiB)", tx_mbps, tx_total as f64 / (1024.0 * 1024.0));
    println!("  Download: {:.1} MB/s  ({:.2} MiB)", rx_mbps, rx_total as f64 / (1024.0 * 1024.0));
    if tx_mbps > 0.0 && rx_mbps > 0.0 {
        let ratio = rx_mbps / tx_mbps;
        println!("  Ratio:    download is {:.2}x upload speed", ratio);
    }
}
