#!/bin/bash

echo "=== Fast Proxy Test ==="

# Start echo server
python3 test_echo_server.py 9999 &
ECHO_PID=$!
sleep 1

# Start proxy  
echo "Starting proxy..."
/home/c2h2/rustproxy/target/release/rustproxy --listen 0.0.0.0:8888 --target 127.0.0.1:9999 --mode tcp &
PROXY_PID=$!
sleep 2

echo "Sending 1000 parallel connections..."
for i in {1..1000}; do
    (echo "test$i" | nc -w 1 127.0.0.1 8888 >/dev/null 2>&1) &
done

wait

# Check if proxy survived
if ps -p $PROXY_PID > /dev/null; then
    echo "✓ Proxy survived 1000 connections!"
    FD_COUNT=$(ls /proc/$PROXY_PID/fd 2>/dev/null | wc -l)
    echo "  File descriptors in use: $FD_COUNT"
else
    echo "✗ Proxy crashed!"
fi

# Cleanup
kill $PROXY_PID 2>/dev/null
kill $ECHO_PID 2>/dev/null

echo "Test completed!"