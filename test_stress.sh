#!/bin/bash

# Start a dummy echo server for testing
echo "Starting dummy echo server on port 9999..."
nc -l -k -p 9999 -c 'cat' &
ECHO_PID=$!

sleep 1

# Start the proxy
echo "Starting rustproxy on port 8888 -> localhost:9999..."
/home/c2h2/rustproxy/target/release/rustproxy --listen 0.0.0.0:8888 --target localhost:9999 --mode tcp &
PROXY_PID=$!

sleep 2

# Function to create connections
test_connections() {
    echo "Testing with $1 concurrent connections..."
    for i in $(seq 1 $1); do
        (echo "Test message $i" | nc localhost 8888) &
    done
    wait
}

# Test with increasing load
test_connections 10
test_connections 50
test_connections 100

echo "Test completed. Checking proxy status..."
ps aux | grep rustproxy | grep -v grep

# Cleanup
echo "Cleaning up..."
kill $PROXY_PID 2>/dev/null
kill $ECHO_PID 2>/dev/null
pkill -f "nc -l -k -p 9999" 2>/dev/null

echo "Done!"