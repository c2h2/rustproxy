#!/bin/bash
echo "Testing high-traffic Mbps calculation..."

# Generate continuous high-bandwidth traffic for 5 seconds
echo "Starting continuous traffic generator in background..."
(
    for i in {1..50}; do
        curl -x http://127.0.0.1:8888 -s http://httpbin.org/bytes/100000 > /dev/null &
        sleep 0.1
    done
    wait
) &
TRAFFIC_PID=$!

sleep 2
echo "Getting stats during traffic..."
curl -s http://127.0.0.1:8080/api/stats | jq '{total_proxies, active_proxies, total_connections, active_connections, total_bytes_sent, total_bytes_received}'

wait $TRAFFIC_PID
echo "Traffic generation complete."
echo "Visit http://127.0.0.1:8080/ to see real-time Mbps chart updates!"
