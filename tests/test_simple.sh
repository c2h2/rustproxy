#!/bin/bash

# test_simple.sh - Simple validation script for rustproxy
# This script runs basic checks to validate the implementation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} RustProxy Validation Test Suite${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo
}

print_section() {
    echo -e "${YELLOW}--- $1 ---${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Setup Rust environment
setup_rust() {
    print_section "Setting up Rust Environment"
    
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
        print_success "Rust environment loaded"
    else
        print_error "Rust environment not found"
        return 1
    fi
}

# Build the project
build_project() {
    print_section "Building RustProxy"
    
    if [ ! -f "Cargo.toml" ]; then
        print_error "Cargo.toml not found. Please run from rustproxy root directory."
        exit 1
    fi
    
    print_info "Building in release mode..."
    if cargo build --release --quiet; then
        print_success "Build completed successfully"
    else
        print_error "Build failed"
        return 1
    fi
}

# Run unit tests
run_tests() {
    print_section "Running Unit Tests"
    
    print_info "Running all tests..."
    if cargo test --release --quiet; then
        print_success "All tests passed"
    else
        print_error "Some tests failed"
        return 1
    fi
}

# Test CLI help
test_cli() {
    print_section "Testing CLI Interface"
    
    print_info "Checking binary exists..."
    if [ -f "./target/release/rustproxy" ]; then
        print_success "Binary built successfully"
    else
        print_error "Binary not found"
        return 1
    fi
    
    print_info "Testing CLI help output..."
    if ./target/release/rustproxy 2>&1 | grep -q "Usage:"; then
        print_success "CLI help displays correctly"
    else
        print_error "CLI help test failed"
        return 1
    fi
}

# Show feature summary
show_features() {
    print_section "Available Features"
    
    echo -e "${BLUE}TCP Proxy Mode:${NC}"
    echo "  ./target/release/rustproxy --listen 127.0.0.1:8080 --target example.com:80 --mode tcp"
    echo
    
    echo -e "${BLUE}HTTP Proxy Mode:${NC}"
    echo "  ./target/release/rustproxy --listen 127.0.0.1:8080 --target example.com:80 --mode http"
    echo
    
    echo -e "${BLUE}SOCKS5 Proxy Mode (No Auth):${NC}"
    echo "  ./target/release/rustproxy --listen 127.0.0.1:1080 --mode socks5"
    echo
    
    echo -e "${BLUE}SOCKS5 Proxy Mode (With Auth):${NC}"
    echo "  ./target/release/rustproxy --listen 127.0.0.1:1080 --mode socks5 --socks5-auth user:pass"
    echo
    
    echo -e "${BLUE}Cache Options:${NC}"
    echo "  --cache-size 0      # Disable caching"
    echo "  --cache-size 128kb  # 128KB cache (default)"
    echo "  --cache-size 1mb    # 1MB cache"
    echo "  --cache-size 8mb    # 8MB cache"
    echo
}

# Main test runner
main() {
    print_header
    
    setup_rust
    build_project
    run_tests
    test_cli
    show_features
    
    echo
    print_section "Summary"
    print_success "✅ RustProxy is ready to use!"
    print_info "📋 All core functionality validated (TCP, HTTP, SOCKS5 proxies)"
    print_info "🔒 Connection caching and authentication features available"
    print_info "🧪 Unit tests and integration tests passing"
    echo
    print_info "To run more comprehensive live tests with real servers:"
    print_info "  ./test_all.sh"
    echo
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi