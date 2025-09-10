#!/bin/bash

# Comprehensive test script for RustProxy

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================="
echo "     RustProxy Comprehensive Test"
echo "========================================="

# Build the project first
echo -e "\n${YELLOW}Building RustProxy...${NC}"
cargo build --release
if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

BINARY="/home/c2h2/rustproxy/target/release/rustproxy"

# Start echo server for testing
echo -e "\n${YELLOW}Starting test echo server on port 9999...${NC}"
python3 test_echo_server.py 9999 &
ECHO_PID=$!
sleep 1

# Function to test a proxy mode
test_proxy() {
    local MODE=$1
    local PORT=$2
    local TEST_CMD=$3
    local PROXY_ARGS=$4
    
    echo -e "\n${YELLOW}Testing $MODE proxy on port $PORT...${NC}"
    
    # Start proxy
    $BINARY $PROXY_ARGS &
    local PROXY_PID=$!
    sleep 2
    
    # Check if proxy started
    if ! ps -p $PROXY_PID > /dev/null; then
        echo -e "${RED}✗ $MODE proxy failed to start${NC}"
        return 1
    fi
    
    # Run test command
    eval $TEST_CMD
    local RESULT=$?
    
    # Check result
    if [ $RESULT -eq 0 ]; then
        echo -e "${GREEN}✓ $MODE proxy test passed${NC}"
    else
        echo -e "${RED}✗ $MODE proxy test failed${NC}"
    fi
    
    # Stop proxy
    kill $PROXY_PID 2>/dev/null
    wait $PROXY_PID 2>/dev/null
    
    return $RESULT
}

# Test 1: TCP Proxy Mode
echo -e "\n${GREEN}=== Test 1: TCP Proxy Mode ===${NC}"
TEST_CMD='echo "TCP_TEST" | nc -w 1 127.0.0.1 8001 | grep -q "TCP_TEST"'
test_proxy "TCP" 8001 "$TEST_CMD" "--listen 0.0.0.0:8001 --target 127.0.0.1:9999 --mode tcp"

# Test 2: HTTP Proxy Mode  
echo -e "\n${GREEN}=== Test 2: HTTP Proxy Mode ===${NC}"
# Start a simple HTTP server for testing
python3 -m http.server 8080 &
HTTP_SERVER_PID=$!
sleep 2

TEST_CMD='curl -x http://127.0.0.1:8002 http://127.0.0.1:8080/ -s -o /dev/null -w "%{http_code}" | grep -q "200"'
test_proxy "HTTP" 8002 "$TEST_CMD" "--listen 0.0.0.0:8002 --mode http"

kill $HTTP_SERVER_PID 2>/dev/null

# Test 3: SOCKS5 Proxy Mode (no auth)
echo -e "\n${GREEN}=== Test 3: SOCKS5 Proxy Mode (No Auth) ===${NC}"
TEST_CMD='curl --socks5 127.0.0.1:8003 http://httpbin.org/ip -s | grep -q "origin"'
test_proxy "SOCKS5" 8003 "$TEST_CMD" "--listen 0.0.0.0:8003 --mode socks5"

# Test 4: SOCKS5 with Authentication
echo -e "\n${GREEN}=== Test 4: SOCKS5 Proxy Mode (With Auth) ===${NC}"
TEST_CMD='curl --socks5 testuser:testpass@127.0.0.1:8004 http://httpbin.org/ip -s | grep -q "origin"'
test_proxy "SOCKS5-AUTH" 8004 "$TEST_CMD" "--listen 0.0.0.0:8004 --mode socks5 --auth testuser:testpass"

# Test 5: Manager Mode
echo -e "\n${GREEN}=== Test 5: Manager Mode ===${NC}"
echo -e "${YELLOW}Starting manager on port 13337...${NC}"
$BINARY --manager --listen 127.0.0.1:13337 &
MANAGER_PID=$!
sleep 2

if ps -p $MANAGER_PID > /dev/null; then
    # Test manager API
    RESPONSE=$(curl -s http://127.0.0.1:13337/stats)
    if echo "$RESPONSE" | grep -q "proxies"; then
        echo -e "${GREEN}✓ Manager API responding${NC}"
        
        # Test web UI
        UI_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:13337/)
        if [ "$UI_RESPONSE" = "200" ]; then
            echo -e "${GREEN}✓ Manager Web UI accessible${NC}"
        else
            echo -e "${RED}✗ Manager Web UI not accessible${NC}"
        fi
    else
        echo -e "${RED}✗ Manager API not responding${NC}"
    fi
    kill $MANAGER_PID 2>/dev/null
else
    echo -e "${RED}✗ Manager failed to start${NC}"
fi

# Test 6: Proxy with Stats Reporting
echo -e "\n${GREEN}=== Test 6: Proxy with Stats Reporting ===${NC}"
echo -e "${YELLOW}Starting manager for stats collection...${NC}"
$BINARY --manager --listen 127.0.0.1:13338 &
MANAGER_PID=$!
sleep 2

echo -e "${YELLOW}Starting TCP proxy with stats reporting...${NC}"
$BINARY --listen 0.0.0.0:8005 --target 127.0.0.1:9999 --mode tcp --stats 127.0.0.1:13338 &
PROXY_PID=$!
sleep 2

# Send some test traffic
for i in {1..5}; do
    echo "STATS_TEST_$i" | nc -w 1 127.0.0.1 8005 >/dev/null 2>&1
done
sleep 2

# Check stats
STATS=$(curl -s http://127.0.0.1:13338/stats)
if echo "$STATS" | grep -q "8005"; then
    echo -e "${GREEN}✓ Stats reporting working${NC}"
    echo "  Stats preview: $(echo $STATS | head -c 100)..."
else
    echo -e "${RED}✗ Stats reporting not working${NC}"
fi

kill $PROXY_PID 2>/dev/null
kill $MANAGER_PID 2>/dev/null

# Test 7: Connection Caching
echo -e "\n${GREEN}=== Test 7: Connection Caching ===${NC}"
echo -e "${YELLOW}Testing with different cache sizes...${NC}"

# Test with 1MB cache
$BINARY --listen 0.0.0.0:8006 --target 127.0.0.1:9999 --mode tcp --cache-size 1mb &
PROXY_PID=$!
sleep 2

if ps -p $PROXY_PID > /dev/null; then
    echo -e "${GREEN}✓ Proxy started with 1MB cache${NC}"
    
    # Send test data
    echo "CACHE_TEST" | nc -w 1 127.0.0.1 8006 | grep -q "CACHE_TEST"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Cache-enabled proxy working${NC}"
    else
        echo -e "${RED}✗ Cache-enabled proxy not working${NC}"
    fi
else
    echo -e "${RED}✗ Failed to start with cache${NC}"
fi
kill $PROXY_PID 2>/dev/null

# Test 8: Stress Test
echo -e "\n${GREEN}=== Test 8: Stress Test (100 concurrent connections) ===${NC}"
$BINARY --listen 0.0.0.0:8007 --target 127.0.0.1:9999 --mode tcp &
PROXY_PID=$!
sleep 2

SUCCESS=0
FAILED=0
for i in {1..100}; do
    (echo "STRESS_$i" | timeout 1 nc 127.0.0.1 8007 2>/dev/null | grep -q "STRESS_$i" && echo -n "." || echo -n "x") &
done
wait

echo ""
if ps -p $PROXY_PID > /dev/null; then
    echo -e "${GREEN}✓ Proxy survived stress test${NC}"
    
    # Check file descriptors
    FD_COUNT=$(ls /proc/$PROXY_PID/fd 2>/dev/null | wc -l)
    echo "  File descriptors in use: $FD_COUNT"
else
    echo -e "${RED}✗ Proxy crashed during stress test${NC}"
fi
kill $PROXY_PID 2>/dev/null

# Test 9: Error Handling
echo -e "\n${GREEN}=== Test 9: Error Handling ===${NC}"

# Test invalid target
echo -e "${YELLOW}Testing with invalid target...${NC}"
$BINARY --listen 0.0.0.0:8008 --target invalid.target.local:99999 --mode tcp &
PROXY_PID=$!
sleep 2

if ps -p $PROXY_PID > /dev/null; then
    echo "TEST" | timeout 2 nc 127.0.0.1 8008 2>/dev/null
    if ps -p $PROXY_PID > /dev/null; then
        echo -e "${GREEN}✓ Proxy handles invalid target gracefully${NC}"
    else
        echo -e "${RED}✗ Proxy crashed on invalid target${NC}"
    fi
    kill $PROXY_PID 2>/dev/null
fi

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $ECHO_PID 2>/dev/null
pkill -f "test_echo_server.py" 2>/dev/null
pkill -f "rustproxy.*800[0-9]" 2>/dev/null
pkill -f "rustproxy.*1333[78]" 2>/dev/null

echo -e "\n========================================="
echo -e "${GREEN}     Test Suite Complete!${NC}"
echo "========================================="

# Summary
echo -e "\nTest Results Summary:"
echo "  • TCP Proxy: Tested"
echo "  • HTTP Proxy: Tested"  
echo "  • SOCKS5 Proxy: Tested"
echo "  • SOCKS5 with Auth: Tested"
echo "  • Manager Mode: Tested"
echo "  • Stats Reporting: Tested"
echo "  • Connection Caching: Tested"
echo "  • Stress Test: Tested"
echo "  • Error Handling: Tested"
