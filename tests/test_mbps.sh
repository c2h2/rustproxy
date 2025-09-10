#!/bin/bash
echo "Testing Mbps calculation accuracy..."

# Get baseline stats
echo "Getting baseline stats..."
stats1=$(curl -s http://127.0.0.1:8080/api/stats)
sent1=$(echo "$stats1" | jq '.total_bytes_sent')
recv1=$(echo "$stats1" | jq '.total_bytes_received')
time1=$(date +%s)

echo "Baseline: Sent=$sent1 bytes, Received=$recv1 bytes at time=$time1"

# Generate traffic for 3 seconds
echo "Generating traffic..."
for i in {1..5}; do
    curl -x http://127.0.0.1:8888 -s http://httpbin.org/bytes/50000 > /dev/null &
done
sleep 3
wait

# Get new stats 
sleep 1  # Wait for stats reporting
stats2=$(curl -s http://127.0.0.1:8080/api/stats)
sent2=$(echo "$stats2" | jq '.total_bytes_sent')
recv2=$(echo "$stats2" | jq '.total_bytes_received')
time2=$(date +%s)

echo "After traffic: Sent=$sent2 bytes, Received=$recv2 bytes at time=$time2"

# Calculate rates manually
sent_diff=$((sent2 - sent1))
recv_diff=$((recv2 - recv1))
time_diff=$((time2 - time1))

if [ $time_diff -gt 0 ]; then
    sent_mbps=$(echo "scale=3; ($sent_diff * 8) / ($time_diff * 1000000)" | bc -l)
    recv_mbps=$(echo "scale=3; ($recv_diff * 8) / ($time_diff * 1000000)" | bc -l)
    
    echo "Manual calculation:"
    echo "  Sent: $sent_diff bytes in $time_diff seconds = $sent_mbps Mbps"  
    echo "  Received: $recv_diff bytes in $time_diff seconds = $recv_mbps Mbps"
    
    echo "Dashboard should show similar rates in the traffic chart."
    echo "Visit http://127.0.0.1:8080/ to verify the chart shows real-time Mbps values."
else
    echo "No time difference detected"
fi
