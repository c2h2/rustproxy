#!/bin/bash

echo "RustProxy Manager System Demo"
echo "============================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to cleanup
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    pkill -f "rustproxy --manager" 2>/dev/null
    pkill -f "rustproxy --listen" 2>/dev/null
    pkill -f "nc -l" 2>/dev/null
    exit 0
}

trap cleanup INT EXIT

# Build if needed
if [ ! -f "./target/release/rustproxy" ]; then
    echo -e "${YELLOW}Building rustproxy...${NC}"
    cargo build --release
fi

# Start manager
echo -e "${GREEN}1. Starting Manager on http://127.0.0.1:13337${NC}"
./target/release/rustproxy --manager --listen 127.0.0.1:13337 &
sleep 2

# Start a simple echo server as target
echo -e "${GREEN}2. Starting test echo server on port 9999${NC}"
while true; do 
    echo -e "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!" | nc -l 127.0.0.1 9999 
done &
ECHO_PID=$!
sleep 1

# Start proxies with stats reporting
echo -e "${GREEN}3. Starting TCP proxy on port 8001 -> localhost:9999${NC}"
RUSTPROXY_MANAGER=127.0.0.1:13337 ./target/release/rustproxy \
    --listen 127.0.0.1:8001 \
    --target 127.0.0.1:9999 \
    --mode tcp &
sleep 1

echo -e "${GREEN}4. Starting HTTP proxy on port 8002${NC}"
RUSTPROXY_MANAGER=127.0.0.1:13337 ./target/release/rustproxy \
    --listen 127.0.0.1:8002 \
    --mode http &
sleep 1

echo -e "${GREEN}5. Starting SOCKS5 proxy on port 8003${NC}"
RUSTPROXY_MANAGER=127.0.0.1:13337 ./target/release/rustproxy \
    --listen 127.0.0.1:8003 \
    --mode socks5 &
sleep 2

echo ""
echo -e "${BLUE}===========================================${NC}"
echo -e "${BLUE}Dashboard URL: http://127.0.0.1:13337${NC}"
echo -e "${BLUE}===========================================${NC}"
echo ""

# Generate some test traffic
echo -e "${YELLOW}6. Generating test traffic...${NC}"
for i in {1..3}; do
    echo -e "  ${GREEN}→${NC} TCP connection #$i through port 8001"
    echo "Test $i" | nc -w 1 127.0.0.1 8001 2>/dev/null &
    sleep 0.5
done

# Check API
echo ""
echo -e "${YELLOW}7. Checking Manager API...${NC}"
echo -e "${GREEN}Health Check:${NC}"
curl -s http://127.0.0.1:13337/api/health | python3 -m json.tool 2>/dev/null || echo "  API is running"

echo ""
echo -e "${GREEN}Active Proxies:${NC}"
curl -s http://127.0.0.1:13337/api/stats | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"  Total Proxies: {data.get('total_proxies', 0)}\")
    print(f\"  Active Proxies: {data.get('active_proxies', 0)}\")
    print(f\"  Total Connections: {data.get('total_connections', 0)}\")
except:
    print('  Waiting for stats...')
" 2>/dev/null

echo ""
echo -e "${BLUE}===========================================${NC}"
echo -e "${GREEN}✓ System is running!${NC}"
echo ""
echo "Open http://127.0.0.1:13337 in your browser"
echo "to see the real-time dashboard"
echo ""
echo "Press Ctrl+C to stop the demo..."
echo -e "${BLUE}===========================================${NC}"

# Keep running
while true; do
    # Generate occasional traffic
    sleep 10
    echo "Test traffic $(date +%s)" | nc -w 1 127.0.0.1 8001 2>/dev/null &
done