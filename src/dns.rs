//! Custom DNS resolver supporting UDP and DNS-over-HTTPS upstreams.
//!
//! When `--dns` is set, all hostname resolution in the proxy goes through the
//! configured upstreams instead of the system resolver.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use once_cell::sync::OnceCell;

static GLOBAL_RESOLVER: OnceCell<Arc<TokioAsyncResolver>> = OnceCell::new();

pub const DEFAULT_CACHE_SIZE: usize = 16_384;
pub const MAX_CACHE_SIZE: usize = 262_144;

/// Initialize the global resolver from a comma-separated spec list.
/// Each spec is one of:
///   - `1.1.1.1`             → UDP on port 53
///   - `1.1.1.1:53`          → UDP on given port
///   - `udp://1.1.1.1[:53]`  → UDP (explicit)
///   - `tcp://1.1.1.1[:53]`  → TCP
///   - `tls://1.1.1.1[:853]` → DNS-over-TLS
///   - `https://host/path`   → DNS-over-HTTPS
///
/// Multiple servers give redundancy: hickory retries the query against the
/// next upstream when one times out or fails.
pub fn init_from_spec(spec: &str, cache_size: usize) -> Result<(), String> {
    let mut config = ResolverConfig::new();
    let mut count = 0;

    for raw in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let ns = parse_one(raw)?;
        config.add_name_server(ns);
        count += 1;
    }

    if count == 0 {
        return Err("--dns requires at least one server".to_string());
    }

    if cache_size > MAX_CACHE_SIZE {
        return Err(format!(
            "--dns-cache-size {} exceeds maximum {}",
            cache_size, MAX_CACHE_SIZE
        ));
    }

    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = false;
    opts.cache_size = cache_size;
    // Retry & redundancy: up to 3 attempts per server rotation, 3s per try.
    // With multiple upstreams configured, failures/timeouts fall through to
    // the next server before retrying.
    opts.attempts = 3;
    opts.timeout = std::time::Duration::from_secs(3);

    let resolver = TokioAsyncResolver::tokio(config, opts);
    GLOBAL_RESOLVER
        .set(Arc::new(resolver))
        .map_err(|_| "DNS resolver already initialized".to_string())?;
    Ok(())
}

fn parse_one(spec: &str) -> Result<NameServerConfig, String> {
    if let Some(rest) = spec.strip_prefix("https://") {
        // DoH: https://host[:port][/path]. We need the resolved IP to bootstrap
        // the connection AND a hostname for TLS SNI / cert validation.
        // Bare IPs are rejected because the cert won't match.
        let authority = match rest.find('/') {
            Some(i) => &rest[..i],
            None => rest,
        };
        let (host, port) = split_host_port(authority, 443);
        if host.parse::<IpAddr>().is_ok() {
            return Err(format!(
                "DoH endpoint must use a hostname, not a bare IP (got {}). \
                 Use e.g. https://cloudflare-dns.com/dns-query or https://dns.google/dns-query",
                host
            ));
        }
        let ip = resolve_via_system(host, port)?;
        let mut ns = NameServerConfig::new(SocketAddr::new(ip, port), Protocol::Https);
        ns.tls_dns_name = Some(host.to_string());
        ns.trust_negative_responses = true;
        return Ok(ns);
    }

    if let Some(rest) = spec.strip_prefix("tls://") {
        // DoT: tls://ip[:853] or tls://hostname[:853]. The TLS name is used
        // for SNI / cert validation — public resolvers like 1.1.1.1, 8.8.8.8
        // and 9.9.9.9 carry IP SANs in their certs, so bare IPs work too.
        let (host, port) = split_host_port(rest, 853);
        let (ip, tls_name) = match host.parse::<IpAddr>() {
            Ok(ip) => (ip, host.to_string()),
            Err(_) => (resolve_via_system(host, port)?, host.to_string()),
        };
        let mut ns = NameServerConfig::new(SocketAddr::new(ip, port), Protocol::Tls);
        ns.tls_dns_name = Some(tls_name);
        ns.trust_negative_responses = true;
        return Ok(ns);
    }

    let (stripped, protocol) = match spec.strip_prefix("tcp://") {
        Some(rest) => (rest, Protocol::Tcp),
        None => (spec.strip_prefix("udp://").unwrap_or(spec), Protocol::Udp),
    };
    let (host, port) = split_host_port(stripped, 53);
    let ip: IpAddr = host
        .parse()
        .map_err(|_| format!("DNS server must be an IP for {}: {}", protocol, host))?;
    Ok(NameServerConfig::new(SocketAddr::new(ip, port), protocol))
}

fn split_host_port(s: &str, default_port: u16) -> (&str, u16) {
    // Handle [::1]:53 style
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let after = &rest[end + 1..];
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port = p.parse().unwrap_or(default_port);
            (h, port)
        }
        _ => (s, default_port),
    }
}

fn resolve_via_system(host: &str, port: u16) -> Result<IpAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve DoH host {}: {}", host, e))?
        .next()
        .map(|sa| sa.ip())
        .ok_or_else(|| format!("no addresses for DoH host {}", host))
}

/// Returns the configured resolver, if `--dns` was set.
pub fn resolver() -> Option<Arc<TokioAsyncResolver>> {
    GLOBAL_RESOLVER.get().cloned()
}

/// Resolve `host:port` to a `SocketAddr`. Uses the configured resolver if set,
/// otherwise falls back to the system resolver (Tokio's default behavior).
pub async fn resolve(addr: &str) -> io::Result<SocketAddr> {
    let (host, port) = parse_host_port(addr)?;

    // Already an IP literal — no DNS needed
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    if let Some(r) = resolver() {
        let lookup = r
            .lookup_ip(host)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("dns: {}", e)))?;
        let ip = lookup.iter().next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("no records for {}", host))
        })?;
        return Ok(SocketAddr::new(ip, port));
    }

    // System fallback
    tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no addresses for {}", addr)))
}

fn parse_host_port(addr: &str) -> io::Result<(&str, u16)> {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..]
                .strip_prefix(':')
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing port"))?
                .parse::<u16>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            return Ok((host, port));
        }
    }
    let (h, p) = addr
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected host:port"))?;
    let port = p
        .parse::<u16>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok((h, port))
}

/// Connect to `addr` (host:port), routing the lookup through the configured
/// resolver when set.
pub async fn tcp_connect(addr: &str) -> io::Result<tokio::net::TcpStream> {
    let sa = resolve(addr).await?;
    tokio::net::TcpStream::connect(sa).await
}

/// Hyper-compatible resolver that delegates to the configured upstream DNS.
/// Implements `tower_service::Service<Name>` so it can be plugged into
/// `hyper::client::HttpConnector::new_with_resolver`.
#[derive(Clone, Default)]
pub struct HyperResolver;

impl tower_service::Service<hyper::client::connect::dns::Name> for HyperResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<Self::Response>> + Send + 'static>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: hyper::client::connect::dns::Name) -> Self::Future {
        let host = name.as_str().to_string();
        Box::pin(async move {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(vec![SocketAddr::new(ip, 0)].into_iter());
            }
            if let Some(r) = resolver() {
                let lookup = r
                    .lookup_ip(host.as_str())
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("dns: {}", e)))?;
                let addrs: Vec<SocketAddr> =
                    lookup.iter().map(|ip| SocketAddr::new(ip, 0)).collect();
                if addrs.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no records for {}", host),
                    ));
                }
                return Ok(addrs.into_iter());
            }
            // System fallback (port 0 — hyper rewrites the port)
            let iter = (host.as_str(), 0u16).to_socket_addrs()?;
            Ok(iter.collect::<Vec<_>>().into_iter())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn parse_udp_tcp_tls_schemes() {
        let ns = parse_one("udp://1.1.1.1").unwrap();
        assert_eq!(ns.protocol, Protocol::Udp);
        assert_eq!(ns.socket_addr, "1.1.1.1:53".parse().unwrap());

        let ns = parse_one("tcp://1.1.1.1").unwrap();
        assert_eq!(ns.protocol, Protocol::Tcp);
        assert_eq!(ns.socket_addr, "1.1.1.1:53".parse().unwrap());

        let ns = parse_one("tcp://8.8.8.8:5353").unwrap();
        assert_eq!(ns.socket_addr, "8.8.8.8:5353".parse().unwrap());

        let ns = parse_one("tls://1.1.1.1").unwrap();
        assert_eq!(ns.protocol, Protocol::Tls);
        assert_eq!(ns.socket_addr, "1.1.1.1:853".parse().unwrap());
        assert_eq!(ns.tls_dns_name.as_deref(), Some("1.1.1.1"));

        // Bare IP / default scheme still UDP
        let ns = parse_one("9.9.9.9").unwrap();
        assert_eq!(ns.protocol, Protocol::Udp);

        // Hostname without tls/https scheme is rejected
        assert!(parse_one("tcp://dns.google").is_err());
    }

    #[tokio::test]
    async fn cache_size_clamped_at_max() {
        // 0 cache size disables caching but is allowed; values over MAX_CACHE_SIZE rejected.
        let err = init_from_spec("1.1.1.1", MAX_CACHE_SIZE + 1).unwrap_err();
        assert!(err.contains("exceeds maximum"), "got: {}", err);
    }

    #[tokio::test]
    #[ignore = "network test"]
    async fn cache_speeds_up_repeat_lookups() {
        // Initialize with a small cache to verify hits occur.
        let _ = init_from_spec("1.1.1.1,8.8.8.8", 1024);

        let host = "example.com:443";

        let t0 = Instant::now();
        let _ = resolve(host).await.expect("first lookup");
        let cold = t0.elapsed();

        // Repeat 50 times — these should be served from cache.
        let t1 = Instant::now();
        for _ in 0..50 {
            let _ = resolve(host).await.expect("warm lookup");
        }
        let warm_total = t1.elapsed();
        let warm_avg = warm_total / 50;

        eprintln!(
            "cold={:?} warm_avg={:?} (50x total {:?})",
            cold, warm_avg, warm_total
        );
        // Warm avg should be at least 10x faster than cold (network RTT vs in-memory map lookup).
        assert!(
            warm_avg * 10 < cold,
            "expected warm_avg ({:?}) << cold ({:?})",
            warm_avg,
            cold
        );
    }
}
