//! Built-in localhost loopback throughput bench (`rustproxy --bench`).
//!
//! Spins up an in-process sink/source server and measures upload + download
//! through each proxy mode (and a direct baseline) on 127.0.0.1.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing::info;

use crate::connection_cache::ConnectionCache;
use crate::http_proxy::HttpProxy;
use crate::socks5_proxy::Socks5Proxy;
use crate::tcp_proxy::TcpProxy;

const CHUNK: usize = 256 * 1024;
const DEFAULT_SIZE_MIB: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Direct,
    Tcp,
    Socks5,
    Http,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Direct => "direct",
            Mode::Tcp => "tcp",
            Mode::Socks5 => "socks5",
            Mode::Http => "http",
        }
    }

    fn parse_list(s: &str) -> Result<Vec<Mode>, String> {
        let mut out = Vec::new();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            out.push(match part.to_ascii_lowercase().as_str() {
                "direct" => Mode::Direct,
                "tcp" => Mode::Tcp,
                "socks5" | "socks" => Mode::Socks5,
                "http" | "connect" => Mode::Http,
                other => {
                    return Err(format!(
                        "unknown bench mode '{}'. Use: direct,tcp,socks5,http",
                        other
                    ));
                }
            });
        }
        if out.is_empty() {
            return Err("no modes specified".into());
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug)]
struct ResultRow {
    mode: Mode,
    upload_mbs: f64,
    download_mbs: f64,
    upload_mib: f64,
    download_mib: f64,
    ok: bool,
    note: &'static str,
}

/// Parse `rustproxy --bench [options]` argv (full process args).
pub(crate) fn parse_bench_args(args: &[String]) -> Result<(usize, Vec<Mode>, usize), String> {
    let mut size_mib = DEFAULT_SIZE_MIB;
    let mut modes = vec![Mode::Direct, Mode::Tcp, Mode::Socks5, Mode::Http];
    let mut warmup = 1usize;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bench" => i += 1,
            "--size" | "-s" => {
                i += 1;
                if i >= args.len() {
                    return Err("--size requires a MiB value".into());
                }
                size_mib = args[i]
                    .parse()
                    .map_err(|_| format!("invalid --size {}", args[i]))?;
                if size_mib == 0 {
                    return Err("--size must be >= 1".into());
                }
                i += 1;
            }
            "--modes" | "-m" => {
                i += 1;
                if i >= args.len() {
                    return Err("--modes requires a list".into());
                }
                modes = Mode::parse_list(&args[i])?;
                i += 1;
            }
            "--warmup" => {
                i += 1;
                if i >= args.len() {
                    return Err("--warmup requires a count".into());
                }
                warmup = args[i]
                    .parse()
                    .map_err(|_| format!("invalid --warmup {}", args[i]))?;
                i += 1;
            }
            "--help" | "-h" => {
                print_bench_help();
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown --bench flag: {}", other));
            }
            _ => i += 1,
        }
    }
    Ok((size_mib, modes, warmup))
}

fn print_bench_help() {
    println!(
        "rustproxy --bench — localhost loopback throughput test (upload + download)\n\
         \n\
         Options:\n\
           --size <MiB>     Payload size per direction (default: {def})\n\
           --modes <list>   Comma-separated: direct,tcp,socks5,http (default: all)\n\
           --warmup <N>     Warm-up iterations discarded before measure (default: 1)\n\
         \n\
         Example:\n\
           rustproxy --bench\n\
           rustproxy --bench --size 512 --modes tcp,socks5\n",
        def = DEFAULT_SIZE_MIB
    );
}

/// Run the full suite. Prints a table to stdout.
pub async fn run_bench(args: &[String]) -> Result<(), String> {
    let (size_mib, modes, warmup) = parse_bench_args(args)?;
    let total = (size_mib as u64) * 1024 * 1024;

    println!("rustproxy --bench");
    println!("  payload : {} MiB per direction", size_mib);
    println!(
        "  modes   : {}",
        modes
            .iter()
            .map(|m| m.name())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  warmup  : {} discarded run(s)", warmup);
    println!();

    let backend = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("backend bind: {}", e))?;
    let backend_addr = backend
        .local_addr()
        .map_err(|e| format!("backend addr: {}", e))?;
    let backend_bytes = Arc::new(AtomicU64::new(total));
    tokio::spawn(run_bench_backend(backend, backend_bytes));
    tokio::task::yield_now().await;

    let mut rows = Vec::new();
    for mode in modes {
        let row = match mode {
            Mode::Direct => {
                measure_mode(mode, total, warmup, || async move {
                    TcpStream::connect(backend_addr).await
                })
                .await
            }
            Mode::Tcp => bench_tcp_mode(backend_addr, total, warmup).await,
            Mode::Socks5 => bench_socks5_mode(backend_addr, total, warmup).await,
            Mode::Http => bench_http_mode(backend_addr, total, warmup).await,
        };
        rows.push(row);
    }

    print_table(&rows);
    if rows.iter().any(|r| !r.ok) {
        return Err("one or more bench modes failed".into());
    }
    Ok(())
}

async fn run_bench_backend(listener: TcpListener, send_bytes: Arc<AtomicU64>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        let _ = stream.set_nodelay(true);
        let nsend = send_bytes.load(Ordering::Relaxed);
        tokio::spawn(async move {
            let mut buf = vec![0u8; CHUNK];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
            let data = vec![0xABu8; CHUNK];
            let mut left = nsend;
            while left > 0 {
                let n = (left as usize).min(CHUNK);
                if stream.write_all(&data[..n]).await.is_err() {
                    return;
                }
                left -= n as u64;
            }
            let _ = stream.shutdown().await;
        });
    }
}

async fn measure_mode<F, Fut>(mode: Mode, total: u64, warmup: usize, connect: F) -> ResultRow
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream, std::io::Error>>,
{
    for _ in 0..warmup {
        if let Ok(s) = connect().await {
            let _ = run_upload_download(s, total).await;
        }
    }
    match connect().await {
        Ok(s) => match run_upload_download(s, total).await {
            Ok((up_mbs, dn_mbs, up_mib, dn_mib)) => ResultRow {
                mode,
                upload_mbs: up_mbs,
                download_mbs: dn_mbs,
                upload_mib: up_mib,
                download_mib: dn_mib,
                ok: true,
                note: "",
            },
            Err(e) => {
                eprintln!("  [{}] transfer failed: {}", mode.name(), e);
                fail_row(mode, "transfer error")
            }
        },
        Err(e) => {
            eprintln!("  [{}] connect failed: {}", mode.name(), e);
            fail_row(mode, "connect error")
        }
    }
}

async fn run_upload_download(
    mut stream: TcpStream,
    total: u64,
) -> Result<(f64, f64, f64, f64), String> {
    let _ = stream.set_nodelay(true);
    let data = vec![0xCDu8; CHUNK];

    let t0 = Instant::now();
    let mut sent = 0u64;
    while sent < total {
        let n = ((total - sent) as usize).min(CHUNK);
        stream
            .write_all(&data[..n])
            .await
            .map_err(|e| format!("upload write: {}", e))?;
        sent += n as u64;
    }
    stream
        .shutdown()
        .await
        .map_err(|e| format!("upload shutdown: {}", e))?;
    let up_s = t0.elapsed().as_secs_f64().max(1e-9);
    let up_mbs = (sent as f64 / 1_000_000.0) / up_s;
    let up_mib = sent as f64 / (1024.0 * 1024.0);

    let t1 = Instant::now();
    let mut got = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => got += n as u64,
            Err(e) => return Err(format!("download read: {}", e)),
        }
    }
    let dn_s = t1.elapsed().as_secs_f64().max(1e-9);
    let dn_mbs = (got as f64 / 1_000_000.0) / dn_s;
    let dn_mib = got as f64 / (1024.0 * 1024.0);

    if got < total {
        return Err(format!("short download: got {} of {} bytes", got, total));
    }
    Ok((up_mbs, dn_mbs, up_mib, dn_mib))
}

async fn bench_tcp_mode(backend: SocketAddr, total: u64, warmup: usize) -> ResultRow {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("  [tcp] bind failed: {}", e);
            return fail_row(Mode::Tcp, "bind error");
        }
    };
    let proxy_addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let backend_s = backend.to_string();
    let accept = tokio::spawn(async move {
        tokio::pin!(stop_rx);
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                acc = listener.accept() => {
                    let Ok((inbound, client_addr)) = acc else { break };
                    let target = backend_s.clone();
                    tokio::spawn(async move {
                        let _ = TcpProxy::connect_and_relay(
                            inbound,
                            client_addr,
                            target,
                            ConnectionCache::new(0),
                            None,
                            Arc::new(AtomicU64::new(0)),
                            Arc::new(AtomicU64::new(0)),
                            256 * 1024,
                        )
                        .await;
                    });
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    let row = measure_mode(Mode::Tcp, total, warmup, move || {
        let a = proxy_addr;
        async move { TcpStream::connect(a).await }
    })
    .await;
    let _ = stop_tx.send(());
    let _ = accept.await;
    row
}

async fn pick_free_addr() -> Result<SocketAddr, String> {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let a = l.local_addr().map_err(|e| e.to_string())?;
    drop(l);
    Ok(a)
}

async fn bench_socks5_mode(backend: SocketAddr, total: u64, warmup: usize) -> ResultRow {
    let listen = match pick_free_addr().await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("  [socks5] {}", e);
            return fail_row(Mode::Socks5, "bind error");
        }
    };
    let bind = listen.to_string();
    let proxy = Socks5Proxy::with_stats(&bind, 0, None, 256 * 1024);
    let (kill_tx, kill_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        tokio::select! {
            r = proxy.start() => {
                if let Err(e) = r {
                    eprintln!("  [socks5] proxy error: {}", e);
                }
            }
            _ = kill_rx => {}
        }
    });

    // Sleep only — a bare TCP probe would complete the handshake then drop
    // and log "early eof" on the SOCKS5 accept path.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let host = backend.ip().to_string();
    let port = backend.port();
    let proxy_a = listen;
    let row = measure_mode(Mode::Socks5, total, warmup, move || {
        let h = host.clone();
        async move { socks5_connect_stream(proxy_a, &h, port).await }
    })
    .await;

    let _ = kill_tx.send(());
    task.abort();
    let _ = task.await;
    row
}

async fn socks5_connect_stream(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    let _ = s.set_nodelay(true);
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "socks5 auth rejected",
        ));
    }
    let host_b = host.as_bytes();
    let mut req = Vec::with_capacity(7 + host_b.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host_b.len() as u8);
    req.extend_from_slice(host_b);
    req.push((port >> 8) as u8);
    req.push((port & 0xff) as u8);
    s.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("socks5 CONNECT rep={:02x}", hdr[1]),
        ));
    }
    match hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            s.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            s.read_exact(&mut skip).await?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "socks5 bad atyp",
            ));
        }
    }
    Ok(s)
}

async fn bench_http_mode(backend: SocketAddr, total: u64, warmup: usize) -> ResultRow {
    let listen = match pick_free_addr().await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("  [http] {}", e);
            return fail_row(Mode::Http, "bind error");
        }
    };
    let bind = listen.to_string();
    // target unused for forward proxy mode; still required by constructor.
    let proxy = HttpProxy::with_stats(&bind, "127.0.0.1:9", 0, None);
    let (kill_tx, kill_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        tokio::select! {
            r = proxy.start() => {
                if let Err(e) = r {
                    eprintln!("  [http] proxy error: {}", e);
                }
            }
            _ = kill_rx => {}
        }
    });

    tokio::time::sleep(Duration::from_millis(80)).await;

    let authority = backend.to_string();
    let proxy_a = listen;
    let row = measure_mode(Mode::Http, total, warmup, move || {
        let a = authority.clone();
        async move { http_connect_stream(proxy_a, &a).await }
    })
    .await;

    let _ = kill_tx.send(());
    task.abort();
    let _ = task.await;
    row
}

async fn http_connect_stream(proxy: SocketAddr, authority: &str) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    let _ = s.set_nodelay(true);
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        authority, authority
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 1];
    loop {
        s.read_exact(&mut tmp).await?;
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CONNECT response too large",
            ));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    if !(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") || head.contains(" 200 "))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("CONNECT failed: {}", head.lines().next().unwrap_or("")),
        ));
    }
    Ok(s)
}

fn fail_row(mode: Mode, note: &'static str) -> ResultRow {
    ResultRow {
        mode,
        upload_mbs: 0.0,
        download_mbs: 0.0,
        upload_mib: 0.0,
        download_mib: 0.0,
        ok: false,
        note,
    }
}

fn print_table(rows: &[ResultRow]) {
    println!();
    println!(
        "{:<10} {:>12} {:>14} {:>10} {:>10}  {}",
        "mode", "upload MB/s", "download MB/s", "up MiB", "dn MiB", "status"
    );
    println!("{}", "-".repeat(74));
    for r in rows {
        let status = if r.ok {
            "ok".to_string()
        } else {
            format!("FAIL {}", r.note)
        };
        println!(
            "{:<10} {:>12.1} {:>14.1} {:>10.1} {:>10.1}  {}",
            r.mode.name(),
            r.upload_mbs,
            r.download_mbs,
            r.upload_mib,
            r.download_mib,
            status
        );
    }
    println!();
    if let (Some(direct), Some(tcp)) = (
        rows.iter().find(|r| r.mode == Mode::Direct && r.ok),
        rows.iter().find(|r| r.mode == Mode::Tcp && r.ok),
    ) {
        if direct.upload_mbs > 0.0 && direct.download_mbs > 0.0 {
            println!(
                "tcp vs direct: upload {:.0}% · download {:.0}% of loopback baseline",
                (tcp.upload_mbs / direct.upload_mbs) * 100.0,
                (tcp.download_mbs / direct.download_mbs) * 100.0
            );
        }
    }
    info!("bench complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes_list() {
        let m = Mode::parse_list("tcp,socks5").unwrap();
        assert_eq!(m, vec![Mode::Tcp, Mode::Socks5]);
    }

    #[test]
    fn parse_bench_defaults() {
        let args = vec!["rustproxy".into(), "--bench".into()];
        let (sz, modes, warm) = parse_bench_args(&args).unwrap();
        assert_eq!(sz, DEFAULT_SIZE_MIB);
        assert_eq!(warm, 1);
        assert!(modes.contains(&Mode::Tcp));
    }

    #[tokio::test]
    async fn bench_direct_and_tcp_smoke() {
        let args = vec![
            "rustproxy".into(),
            "--bench".into(),
            "--size".into(),
            "1".into(),
            "--modes".into(),
            "direct,tcp".into(),
            "--warmup".into(),
            "0".into(),
        ];
        run_bench(&args).await.expect("bench smoke");
    }
}
