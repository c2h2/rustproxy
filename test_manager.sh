#!/bin/bash

echo "RustProxy Manager System Test"
echo "============================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Start the manager
echo -e "${GREEN}Starting RustProxy Manager on 127.0.0.1:13337...${NC}"
./target/release/rustproxy --manager --listen 127.0.0.1:13337 &
MANAGER_PID=$!
sleep 2

# Start multiple proxy instances with stats reporting
echo -e "${GREEN}Starting TCP proxy on port 8001...${NC}"
RUSTPROXY_MANAGER=127.0.0.1:13337 ./target/release/rustproxy --listen 127.0.0.1:8001 --target example.com:80 --mode tcp &
TCP_PID=$!
sleep 1

echo -e "${GREEN}Starting HTTP proxy on port 8002...${NC}"
RUSTPROXY_MANAGER=127.0.0.1:13337 ./target/release/rustproxy --listen 127.0.0.1:8002 --mode http &
HTTP_PID=$!
sleep 1

echo -e "${GREEN}Starting SOCKS5 proxy on port 8003...${NC}"
RUSTPROXY_MANAGER=127.0.0.1:13337 ./target/release/rustproxy --listen 127.0.0.1:8003 --mode socks5 &
SOCKS5_PID=$!
sleep 1

echo ""
echo -e "${YELLOW}All proxies started!${NC}"
echo ""
echo "Manager Dashboard: http://127.0.0.1:13337"
echo "TCP Proxy: 127.0.0.1:8001"
echo "HTTP Proxy: 127.0.0.1:8002"
echo "SOCKS5 Proxy: 127.0.0.1:8003"
echo ""
echo -e "${YELLOW}Open http://127.0.0.1:13337 in your browser to see the real-time dashboard${NC}"
echo ""
echo "Press Ctrl+C to stop all services..."

# Function to cleanup on exit
cleanup() {
    echo ""
    echo -e "${RED}Stopping all services...${NC}"
    kill $MANAGER_PID $TCP_PID $HTTP_PID $SOCKS5_PID 2>/dev/null
    exit 0
}

# Set trap to cleanup on Ctrl+C
trap cleanup INT

# Wait forever
while true; do
    sleep 1
done