#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "=== Testing RustProxy with File Descriptor Fix ==="

# Start echo server
echo "Starting echo server on port 9999..."
python3 test_echo_server.py 9999 &
ECHO_PID=$!
sleep 1

# Start proxy
echo "Starting rustproxy on port 8888 -> 127.0.0.1:9999..."
/home/c2h2/rustproxy/target/release/rustproxy --listen 0.0.0.0:8888 --target 127.0.0.1:9999 --mode tcp &
PROXY_PID=$!
sleep 2

# Test function
test_load() {
    local count=$1
    echo -e "\n${GREEN}Testing with $count connections...${NC}"
    
    SUCCESS=0
    FAILED=0
    
    for i in $(seq 1 $count); do
        RESPONSE=$(echo "test$i" | timeout 1 nc 127.0.0.1 8888 2>/dev/null)
        if [ "$RESPONSE" = "test$i" ]; then
            ((SUCCESS++))
        else
            ((FAILED++))
        fi
        
        # Show progress every 100 connections
        if [ $((i % 100)) -eq 0 ]; then
            echo "  Progress: $i/$count (Success: $SUCCESS, Failed: $FAILED)"
        fi
    done
    
    echo -e "  ${GREEN}Results: Success=$SUCCESS, Failed=$FAILED${NC}"
    
    # Check if proxy is still running
    if ps -p $PROXY_PID > /dev/null; then
        echo -e "  ${GREEN}✓ Proxy still running${NC}"
    else
        echo -e "  ${RED}✗ Proxy crashed!${NC}"
        exit 1
    fi
}

# Run tests
test_load 100
test_load 500
test_load 1000

echo -e "\n${GREEN}All tests completed successfully!${NC}"

# Check file descriptors
echo -e "\nFile descriptor usage:"
if [ -d /proc/$PROXY_PID/fd ]; then
    FD_COUNT=$(ls /proc/$PROXY_PID/fd | wc -l)
    echo "  Proxy process is using $FD_COUNT file descriptors"
fi

# Cleanup
echo -e "\nCleaning up..."
kill $PROXY_PID 2>/dev/null
kill $ECHO_PID 2>/dev/null

echo "Done!"