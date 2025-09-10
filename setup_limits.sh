#!/bin/bash

# Script to configure Linux system for high file descriptor limits

echo "=== Configuring System File Descriptor Limits ==="

# Check current limits
echo "Current soft limit: $(ulimit -n)"
echo "Current hard limit: $(ulimit -Hn)"

# Set session limits (temporary, until logout)
ulimit -n 1000000

# To make permanent system-wide changes, add to /etc/security/limits.conf:
echo ""
echo "To make permanent changes, add these lines to /etc/security/limits.conf:"
echo "* soft nofile 1000000"
echo "* hard nofile 1000000"
echo ""

# For systemd services, also configure:
echo "For systemd services, edit /etc/systemd/system.conf and /etc/systemd/user.conf:"
echo "DefaultLimitNOFILE=1000000"
echo ""

# Check system-wide max file descriptors
echo "System-wide max file descriptors:"
cat /proc/sys/fs/file-max

echo ""
echo "To increase system-wide limit, run:"
echo "echo 2000000 | sudo tee /proc/sys/fs/file-max"

# Check current TCP settings
echo ""
echo "=== TCP Settings for High Connection Count ==="
echo "Current TCP settings:"
echo "  net.ipv4.tcp_fin_timeout = $(sysctl -n net.ipv4.tcp_fin_timeout 2>/dev/null || echo 'N/A')"
echo "  net.ipv4.ip_local_port_range = $(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo 'N/A')"
echo "  net.core.somaxconn = $(sysctl -n net.core.somaxconn 2>/dev/null || echo 'N/A')"
echo "  net.ipv4.tcp_tw_reuse = $(sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null || echo 'N/A')"

echo ""
echo "To optimize for high connection count, add to /etc/sysctl.conf:"
echo "net.ipv4.tcp_fin_timeout = 30"
echo "net.ipv4.ip_local_port_range = 1024 65535"
echo "net.core.somaxconn = 65535"
echo "net.ipv4.tcp_tw_reuse = 1"
echo "net.ipv4.tcp_keepalive_time = 60"
echo "net.ipv4.tcp_keepalive_intvl = 10"
echo "net.ipv4.tcp_keepalive_probes = 6"
echo ""
echo "Then run: sudo sysctl -p"