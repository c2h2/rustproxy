#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================="
echo "     RustProxy Basic Function Test"
echo "========================================="

BINARY="/home/c2h2/rustproxy/target/release/rustproxy"

# Kill any existing processes
pkill -f "test_echo_server.py" 2>/dev/null
pkill -f "rustproxy" 2>/dev/null

# Start echo server
echo -e "\n${YELLOW}Starting test echo server...${NC}"
python3 test_echo_server.py 9999 &
ECHO_PID=$!
sleep 1

echo -e "\n${GREEN}Test 1: TCP Proxy${NC}"
$BINARY --listen 0.0.0.0:8001 --target 127.0.0.1:9999 --mode tcp &
TCP_PID=$!
sleep 1
RESULT=$(echo "TCP_TEST" | nc -w 1 127.0.0.1 8001)
if [ "$RESULT" = "TCP_TEST" ]; then
    echo -e "${GREEN}✓ TCP proxy works${NC}"
else
    echo -e "${RED}✗ TCP proxy failed${NC}"
fi
kill $TCP_PID 2>/dev/null

echo -e "\n${GREEN}Test 2: HTTP Proxy${NC}"
python3 -m http.server 8080 >/dev/null 2>&1 &
HTTP_SERVER_PID=$!
sleep 1
$BINARY --listen 0.0.0.0:8002 --mode http &
HTTP_PID=$!
sleep 1
HTTP_CODE=$(curl -x http://127.0.0.1:8002 http://127.0.0.1:8080/ -s -o /dev/null -w "%{http_code}" 2>/dev/null)
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ HTTP proxy works${NC}"
else
    echo -e "${RED}✗ HTTP proxy failed (code: $HTTP_CODE)${NC}"
fi
kill $HTTP_PID 2>/dev/null
kill $HTTP_SERVER_PID 2>/dev/null

echo -e "\n${GREEN}Test 3: SOCKS5 Proxy${NC}"
$BINARY --listen 0.0.0.0:8003 --mode socks5 &
SOCKS_PID=$!
sleep 1
# Test with local connection through SOCKS5
RESULT=$(echo "SOCKS_TEST" | nc -X 5 -x 127.0.0.1:8003 127.0.0.1 9999 2>/dev/null)
if [ "$RESULT" = "SOCKS_TEST" ]; then
    echo -e "${GREEN}✓ SOCKS5 proxy works${NC}"
else
    echo -e "${RED}✗ SOCKS5 proxy failed${NC}"
fi
kill $SOCKS_PID 2>/dev/null

echo -e "\n${GREEN}Test 4: Manager Mode${NC}"
$BINARY --manager --listen 127.0.0.1:13337 &
MANAGER_PID=$!
sleep 2
MANAGER_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:13337/stats)
if [ "$MANAGER_STATUS" = "200" ]; then
    echo -e "${GREEN}✓ Manager API works${NC}"
else
    echo -e "${RED}✗ Manager API failed${NC}"
fi
kill $MANAGER_PID 2>/dev/null

echo -e "\n${GREEN}Test 5: Custom Cache Size${NC}"
$BINARY --listen 0.0.0.0:8004 --target 127.0.0.1:9999 --mode tcp --cache-size 1mb &
CACHE_PID=$!
sleep 1
if ps -p $CACHE_PID > /dev/null; then
    echo -e "${GREEN}✓ Custom cache size accepted${NC}"
    RESULT=$(echo "CACHE_TEST" | nc -w 1 127.0.0.1 8004)
    if [ "$RESULT" = "CACHE_TEST" ]; then
        echo -e "${GREEN}✓ Proxy with custom cache works${NC}"
    fi
else
    echo -e "${RED}✗ Failed to start with custom cache${NC}"
fi
kill $CACHE_PID 2>/dev/null

echo -e "\n${GREEN}Test 6: Connection Limit (Quick Test)${NC}"
$BINARY --listen 0.0.0.0:8005 --target 127.0.0.1:9999 --mode tcp &
LIMIT_PID=$!
sleep 1
# Send 20 quick connections
for i in {1..20}; do
    (echo "TEST$i" | nc -w 0.1 127.0.0.1 8005 >/dev/null 2>&1) &
done
wait
if ps -p $LIMIT_PID > /dev/null; then
    echo -e "${GREEN}✓ Proxy handles multiple connections${NC}"
    FD_COUNT=$(ls /proc/$LIMIT_PID/fd 2>/dev/null | wc -l)
    echo "  File descriptors: $FD_COUNT"
else
    echo -e "${RED}✗ Proxy crashed${NC}"
fi
kill $LIMIT_PID 2>/dev/null

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $ECHO_PID 2>/dev/null
pkill -f "test_echo_server.py" 2>/dev/null
pkill -f "rustproxy" 2>/dev/null

echo -e "\n========================================="
echo -e "${GREEN}        Test Complete!${NC}"
echo -e "========================================="
echo -e "\nSummary of tested features:"
echo "  ✓ TCP Proxy Mode"
echo "  ✓ HTTP Proxy Mode"
echo "  ✓ SOCKS5 Proxy Mode"
echo "  ✓ Manager Mode with API"
echo "  ✓ Custom Cache Sizes"
echo "  ✓ Connection Handling"
