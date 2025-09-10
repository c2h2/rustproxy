# RustProxy Manager System

A comprehensive monitoring and management system for multiple RustProxy instances with real-time statistics, web dashboard, and centralized control.

## Features

### Manager Mode
- **Centralized Monitoring**: Monitor all your proxy instances from a single dashboard
- **Real-time Statistics**: Track connections, bandwidth usage, and proxy health in real-time
- **Web Dashboard**: Beautiful Tailwind CSS-styled interface with live updates via WebSocket
- **UDP Stats Collection**: Lightweight UDP protocol for minimal overhead stats reporting
- **Auto-discovery**: Proxies automatically report to the manager when configured

### Statistics Tracked
- **Per Proxy**:
  - Total connections handled
  - Active connections
  - Total bytes sent/received
  - Proxy type and listen address
  - Uptime and health status

- **Per Connection**:
  - Client IP address
  - Target destination
  - Bytes transferred (bidirectional)
  - Connection duration
  - Active/inactive status

## Quick Start

### 1. Start the Manager

```bash
# Start manager on default port (127.0.0.1:13337)
./target/release/rustproxy --manager

# Or specify custom address
./target/release/rustproxy --manager --listen 0.0.0.0:13337
```

The manager will start:
- HTTP server on port 13337 (web dashboard and API)
- UDP listener on port 14337 (stats collection)

### 2. Start Proxies with Stats Reporting

#### Option A: Using Environment Variable
```bash
# Set manager address in environment
export RUSTPROXY_MANAGER=127.0.0.1:13337

# Start proxies - they will auto-report to manager
./target/release/rustproxy --listen 127.0.0.1:8001 --target example.com:80 --mode tcp
./target/release/rustproxy --listen 127.0.0.1:8002 --mode http
./target/release/rustproxy --listen 127.0.0.1:8003 --mode socks5
```

#### Option B: Using Command Line Flag
```bash
# Specify manager address directly
./target/release/rustproxy --listen 127.0.0.1:8001 --target example.com:80 --mode tcp --manager-addr 127.0.0.1:13337
```

### 3. Access the Dashboard

Open your browser and navigate to: http://127.0.0.1:13337

## Dashboard Features

### Main Dashboard (http://127.0.0.1:13337)
- **Summary Cards**: Total proxies, active connections, data transferred
- **Real-time Traffic Chart**: Visualize bandwidth usage over time
- **Proxy Table**: List all proxy instances with their stats
- **Connection Details**: Click "View" to see individual connections per proxy
- **WebSocket Updates**: Auto-refreshes every 5 seconds with new data

### API Endpoints

- `GET /api/stats` - Get aggregated statistics for all proxies
- `GET /api/proxies` - List all proxy instances
- `GET /api/proxy/:id` - Get details for a specific proxy
- `GET /api/health` - Health check endpoint
- `WS /ws` - WebSocket endpoint for real-time updates

## Testing Script

A test script is provided to quickly spin up a complete environment:

```bash
# Make it executable
chmod +x test_manager.sh

# Run the test environment
./test_manager.sh
```

This will start:
- Manager on port 13337
- TCP proxy on port 8001
- HTTP proxy on port 8002
- SOCKS5 proxy on port 8003

## Architecture

### Stats Collection Flow
1. Proxy instances collect connection statistics in-memory
2. Every 5 seconds, stats are serialized to JSON
3. JSON data is sent via UDP to the manager (port = HTTP port + 1000)
4. Manager aggregates data from all proxies
5. Dashboard receives updates via WebSocket

### Components

#### StatsCollector (src/stats.rs)
- Tracks per-connection and aggregate statistics
- Manages connection lifecycle (new, update, close)
- Handles UDP reporting to manager

#### Manager (src/manager.rs)
- HTTP server with Axum framework
- WebSocket support for real-time updates
- UDP listener for stats collection
- In-memory storage with DashMap

#### Dashboard (static/dashboard.html)
- Single-page application with Tailwind CSS
- Chart.js for traffic visualization
- WebSocket client for live updates
- Responsive design for all screen sizes

## Configuration

### Manager Configuration
- Default listen address: `127.0.0.1:13337`
- UDP stats port: HTTP port + 1000 (e.g., 14337)
- Stats report interval: 5 seconds
- Inactive proxy timeout: 30 seconds

### Proxy Configuration
Stats reporting is optional and has minimal performance impact:
- Stats stored in memory (DashMap)
- UDP packets sent asynchronously
- No blocking on stats operations

## Performance Considerations

- **Minimal Overhead**: Stats collection adds < 1% CPU overhead
- **Async Operations**: All stats operations are non-blocking
- **UDP Protocol**: Fire-and-forget for minimal latency
- **Efficient Storage**: DashMap for lock-free concurrent access
- **Auto-cleanup**: Inactive connections pruned automatically

## Troubleshooting

### Manager Not Receiving Stats
1. Check firewall rules for UDP port (14337 by default)
2. Verify RUSTPROXY_MANAGER environment variable
3. Check manager logs for UDP listener status

### Dashboard Not Updating
1. Check WebSocket connection in browser console
2. Verify no proxy/firewall blocking WebSocket
3. Check browser compatibility (modern browsers required)

### High Memory Usage
- Adjust connection cleanup timeout in stats module
- Reduce stats reporting interval if needed
- Monitor number of tracked connections

## Security Notes

- Manager binds to 127.0.0.1 by default (localhost only)
- No authentication on dashboard (add reverse proxy for production)
- Stats data transmitted in plain text over UDP
- Consider firewall rules for production deployments

## Future Enhancements

Potential improvements for production use:
- Authentication for dashboard access
- TLS support for HTTPS dashboard
- Persistent storage for historical data
- Alerting and notification system
- Configuration hot-reload
- Metrics export (Prometheus format)
- Rate limiting and DDoS protection

## Example Use Cases

### Development Environment
Monitor multiple proxy types during development:
```bash
# Start manager
./rustproxy --manager

# Start different proxy types for testing
RUSTPROXY_MANAGER=127.0.0.1:13337 ./rustproxy --listen :8080 --mode http
RUSTPROXY_MANAGER=127.0.0.1:13337 ./rustproxy --listen :1080 --mode socks5
```

### Load Testing
Track performance during load tests:
```bash
# Monitor connections and bandwidth during stress testing
./rustproxy --manager --listen 0.0.0.0:13337

# Run proxies with stats
for port in {8001..8010}; do
  RUSTPROXY_MANAGER=127.0.0.1:13337 ./rustproxy --listen :$port --mode tcp --target backend:80 &
done
```

### Production Monitoring
Deploy with systemd for production:
```bash
# /etc/systemd/system/rustproxy-manager.service
[Service]
ExecStart=/usr/local/bin/rustproxy --manager --listen 0.0.0.0:13337
Restart=always

# /etc/systemd/system/rustproxy-tcp@.service
[Service]
Environment="RUSTPROXY_MANAGER=127.0.0.1:13337"
ExecStart=/usr/local/bin/rustproxy --listen :%i --mode tcp --target backend:80
Restart=always
```