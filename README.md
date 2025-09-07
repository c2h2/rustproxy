# RustProxy

A high-performance proxy server written in Rust with configurable connection caching.

## Features

- **TCP Proxy**: Forward TCP connections to target servers
- **HTTP Proxy**: Forward HTTP requests to target servers  
- **SOCKS5 Proxy**: Full SOCKS5 server with optional authentication
- **Connection Caching**: Configurable connection pooling to improve performance
- **Async/Await**: Built with Tokio for high-performance async networking
- **Flexible Configuration**: Command-line configuration with sensible defaults

## Installation

Make sure you have Rust installed, then build the project:

```bash
cargo build --release
```

## Usage

```bash
rustproxy --listen <address:port> [--target <address:port>] --mode <tcp|http|socks5> [--cache-size <size>] [--socks5-auth <user:pass>]
```

### Options

- `--listen <address:port>` - Address to listen on
- `--target <address:port>` - Address to proxy requests to (required for tcp/http modes)
- `--mode <tcp|http|socks5>` - Proxy mode
- `--cache-size <size>` - Connection cache size (default: 128KB)
  - Examples: `0`, `none`, `128kb`, `1mb`, `8mb`
- `--socks5-auth <user:pass>` - SOCKS5 authentication credentials (optional)

### Examples

**TCP Proxy with default caching (128KB):**
```bash
rustproxy --listen 127.0.0.1:8080 --target 192.168.1.100:9000 --mode tcp
```

**TCP Proxy with 1MB connection cache:**
```bash
rustproxy --listen 127.0.0.1:8080 --target 192.168.1.100:9000 --mode tcp --cache-size 1mb
```

**TCP Proxy with caching disabled:**
```bash
rustproxy --listen 127.0.0.1:8080 --target 192.168.1.100:9000 --mode tcp --cache-size 0
```

**HTTP Proxy:**
```bash
rustproxy --listen 127.0.0.1:8080 --target 192.168.1.100:9000 --mode http
```

**SOCKS5 Proxy (no authentication):**
```bash
rustproxy --listen 127.0.0.1:1080 --mode socks5
```

**SOCKS5 Proxy with authentication:**
```bash
rustproxy --listen 127.0.0.1:1080 --mode socks5 --socks5-auth username:password
```

**SOCKS5 Proxy with custom cache size:**
```bash
rustproxy --listen 127.0.0.1:1080 --mode socks5 --cache-size 2mb
```

## Architecture

- **TCP Proxy** (`src/tcp_proxy.rs`): Handles raw TCP connection forwarding
- **HTTP Proxy** (`src/http_proxy.rs`): Handles HTTP request/response forwarding
- **SOCKS5 Proxy** (`src/socks5_proxy.rs`): Full SOCKS5 server implementation with authentication support
- **Connection Cache** (`src/connection_cache.rs`): Manages connection pooling for performance optimization
- **Main** (`src/main.rs`): Command-line interface and application startup

## SOCKS5 Features

- **Protocol Compliance**: Full SOCKS5 protocol implementation (RFC 1928)
- **Authentication Methods**:
  - No authentication (anonymous access)
  - Username/password authentication (RFC 1929)
- **Connection Types**: CONNECT command support (most common use case)
- **Address Types**: IPv4, IPv6, and domain name resolution
- **Connection Caching**: Reuse connections for improved performance
- **Error Handling**: Proper SOCKS5 error responses for various failure conditions

### SOCKS5 Client Configuration

To use the SOCKS5 proxy with various applications:

**cURL:**
```bash
curl --socks5 127.0.0.1:1080 https://example.com
curl --socks5-hostname 127.0.0.1:1080 https://example.com  # DNS through proxy
```

**SSH:**
```bash
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@target.com
```

**Firefox:** 
- Go to Settings → Network Settings → Manual proxy configuration
- Set SOCKS Host: 127.0.0.1, Port: 1080, SOCKS v5

**Environment Variables:**
```bash
export ALL_PROXY=socks5://127.0.0.1:1080
export all_proxy=socks5://127.0.0.1:1080
```

## Development

### Running Tests

**Quick validation:**
```bash
./test_simple.sh
```

**Unit tests only:**
```bash
cargo test
```

**Comprehensive integration tests:**
```bash
./test_all.sh
```

### Running Benchmarks

```bash
cargo bench
```

### Dependencies

- **tokio**: Async runtime
- **hyper**: HTTP client/server library  
- **tracing**: Structured logging
- **bytes**: Byte buffer utilities
- **futures-util**: Future utilities

## License

[Add your license information here]