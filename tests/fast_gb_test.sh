#!/bin/bash
echo "🚀 Fast gigabyte test using rapid small requests..."

# Get baseline
baseline_stats=$(curl -s http://127.0.0.1:8080/api/stats)
baseline_sent=$(echo "$baseline_stats" | jq '.total_bytes_sent')
start_time=$(date +%s.%N)

echo "📊 Baseline: $(echo "scale=2; $baseline_sent / 1048576" | bc -l) MB"

# Generate rapid traffic - 1000 requests of 1MB each
echo "🔥 Generating 1000 x 1MB requests in parallel batches..."

for batch in {1..20}; do
    echo "   Batch $batch/20..."
    for i in {1..50}; do
        curl -x http://127.0.0.1:8888 -s "http://httpbin.org/bytes/1048576" > /dev/null &  # 1MB each
    done
    wait
    
    # Check progress every 5 batches
    if [ $((batch % 5)) -eq 0 ]; then
        current_stats=$(curl -s http://127.0.0.1:8080/api/stats)
        current_sent=$(echo "$current_stats" | jq '.total_bytes_sent')
        total_mb=$(echo "scale=2; ($current_sent - $baseline_sent) / 1048576" | bc -l)
        echo "   Progress: ${total_mb} MB transferred"
    fi
done

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc -l)

# Final stats
final_stats=$(curl -s http://127.0.0.1:8080/api/stats)
final_sent=$(echo "$final_stats" | jq '.total_bytes_sent')
final_recv=$(echo "$final_stats" | jq '.total_bytes_received')

total_sent=$(echo "$final_sent - $baseline_sent" | bc -l)
total_recv=$(echo "$final_recv - $baseline_sent" | bc -l)

sent_mb=$(echo "scale=2; $total_sent / 1048576" | bc -l)
recv_mb=$(echo "scale=2; $total_recv / 1048576" | bc -l)
total_mb=$(echo "scale=2; ($total_sent + $total_recv) / 1048576" | bc -l)

avg_mbps=$(echo "scale=2; ($total_sent + $total_recv) * 8 / ($duration * 1000000)" | bc -l)

echo "✅ Test completed in ${duration}s"
echo "📊 Results:"
echo "   Sent: ${sent_mb} MB"
echo "   Received: ${recv_mb} MB" 
echo "   Total: ${total_mb} MB"
echo "   Average throughput: ${avg_mbps} Mbps"
echo ""
echo "🎯 Dashboard should now show GB-scale data!"
echo "   Visit http://127.0.0.1:8080/ to verify the chart and counters"
