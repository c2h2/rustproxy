#!/bin/bash
echo "🚀 Starting gigabyte-scale traffic test..."

# Function to format bytes
format_bytes() {
    local bytes=$1
    if [ $bytes -ge 1073741824 ]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc -l) GB"
    elif [ $bytes -ge 1048576 ]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc -l) MB"
    elif [ $bytes -ge 1024 ]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc -l) KB"
    else
        echo "$bytes B"
    fi
}

# Get baseline stats
echo "📊 Getting baseline stats..."
baseline=$(curl -s http://127.0.0.1:8080/api/stats)
baseline_sent=$(echo "$baseline" | jq '.total_bytes_sent')
baseline_recv=$(echo "$baseline" | jq '.total_bytes_received')
start_time=$(date +%s)

echo "   Baseline: $(format_bytes $baseline_sent) sent, $(format_bytes $baseline_recv) received"

# Generate sustained traffic - targeting ~1GB total
echo "🔥 Generating sustained gigabyte traffic (this may take 30-60 seconds)..."
echo "   Downloading 100 x 10MB files concurrently..."

# Create background traffic generator
(
    for batch in {1..10}; do
        echo "   Batch $batch/10..."
        for i in {1..10}; do
            curl -x http://127.0.0.1:8888 -s "http://httpbin.org/bytes/10485760" > /dev/null &  # 10MB each
        done
        # Wait for batch to complete before starting next
        wait
        
        # Show progress
        current_stats=$(curl -s http://127.0.0.1:8080/api/stats)
        current_sent=$(echo "$current_stats" | jq '.total_bytes_sent')
        current_recv=$(echo "$current_stats" | jq '.total_bytes_received')
        total_sent=$((current_sent - baseline_sent))
        total_recv=$((current_recv - baseline_recv))
        echo "   Progress: $(format_bytes $total_sent) sent, $(format_bytes $total_recv) received"
    done
) &

TRAFFIC_PID=$!

# Monitor progress every 5 seconds
echo "📈 Monitoring dashboard performance during high-volume transfer..."
monitor_count=0
while kill -0 $TRAFFIC_PID 2>/dev/null; do
    sleep 5
    monitor_count=$((monitor_count + 1))
    
    current_stats=$(curl -s http://127.0.0.1:8080/api/stats)
    current_sent=$(echo "$current_stats" | jq '.total_bytes_sent')
    current_recv=$(echo "$current_stats" | jq '.total_bytes_received')
    active_conns=$(echo "$current_stats" | jq '.active_connections')
    total_conns=$(echo "$current_stats" | jq '.total_connections')
    
    total_sent=$((current_sent - baseline_sent))
    total_recv=$((current_recv - baseline_recv))
    
    echo "   Monitor $monitor_count: $(format_bytes $total_sent) sent, $(format_bytes $total_recv) received, $active_conns/$total_conns connections"
done

# Wait for completion
wait $TRAFFIC_PID
end_time=$(date +%s)
duration=$((end_time - start_time))

echo "✅ Traffic generation complete!"

# Get final stats
final_stats=$(curl -s http://127.0.0.1:8080/api/stats)
final_sent=$(echo "$final_stats" | jq '.total_bytes_sent')
final_recv=$(echo "$final_stats" | jq '.total_bytes_received')
final_conns=$(echo "$final_stats" | jq '.total_connections')

total_sent=$((final_sent - baseline_sent))
total_recv=$((final_recv - baseline_recv))

echo "📊 Final Results:"
echo "   Duration: ${duration}s"
echo "   Data sent: $(format_bytes $total_sent)"
echo "   Data received: $(format_bytes $total_recv)"
echo "   Total connections: $final_conns"
echo "   Average throughput: $(echo "scale=2; ($total_sent + $total_recv) * 8 / ($duration * 1000000)" | bc -l) Mbps"

echo ""
echo "🎯 Dashboard Test Results:"
echo "   - Visit http://127.0.0.1:8080/ to verify:"
echo "     • Chart shows accurate Mbps calculations"
echo "     • No browser crashes or performance issues"
echo "     • Data counters show GB-scale values correctly"
echo "     • WebSocket updates remain responsive"
