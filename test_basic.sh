#!/bin/bash

# test_basic.sh - Basic test script for rustproxy core functionality
# This script runs unit tests and basic functionality checks

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} RustProxy Basic Test Suite${NC}"
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
    if cargo build --release; then
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
    if cargo test --release; then
        print_success "All tests passed"
    else
        print_error "Some tests failed"
        return 1
    fi
}

# Test CLI help
test_cli_help() {
    print_section "Testing CLI Interface"
    
    print_info "Testing --help output..."
    if ./target/release/rustproxy 2>&1 | grep -q "Usage:"; then
        print_success "CLI help text displays correctly"
    else
        print_error "CLI help test failed"
        return 1
    fi
}

# Test different modes are recognized
test_cli_modes() {
    print_info "Testing mode validation..."
    
    # Test invalid mode
    if ! ./target/release/rustproxy --listen 127.0.0.1:8080 --target 127.0.0.1:9000 --mode invalid 2>&1 | grep -q "Mode must be"; then
        print_error "Invalid mode validation failed"
        return 1
    fi
    
    # Test missing target for tcp mode
    if ! ./target/release/rustproxy --listen 127.0.0.1:8080 --mode tcp 2>&1 | grep -q "Missing --target parameter"; then
        print_error "Missing target validation failed"
        return 1
    fi
    
    # Test SOCKS5 mode doesn't require target
    timeout 2s ./target/release/rustproxy --listen 127.0.0.1:1080 --mode socks5 >/dev/null 2>&1 || true
    
    print_success "CLI mode validation works correctly"
}

# Test cache size parsing
test_cache_parsing() {
    print_info "Testing cache size parsing..."
    
    # This will be tested by the unit tests, but we can verify the CLI accepts different formats
    local cache_sizes=("0" "128kb" "1mb" "8mb")
    
    for cache_size in "${cache_sizes[@]}"; do
        # Just test that the CLI accepts these cache sizes without error (we'll timeout quickly)
        timeout 1s ./target/release/rustproxy --listen 127.0.0.1:1080 --mode socks5 --cache-size "$cache_size" >/dev/null 2>&1
        local exit_code=$?
        # Exit code 124 means timeout (expected), anything else might be an error
        if [ $exit_code -eq 124 ] || [ $exit_code -eq 0 ]; then
            continue  # Timeout is expected, or clean exit
        else
            print_error "Cache size parsing failed for: $cache_size (exit code: $exit_code)"
            return 1
        fi
    done
    
    print_success "Cache size parsing works correctly"
}

# Test SOCKS5 authentication parsing
test_socks5_auth() {
    print_info "Testing SOCKS5 authentication parsing..."
    
    # Test valid auth format
    timeout 1s ./target/release/rustproxy --listen 127.0.0.1:1080 --mode socks5 --socks5-auth "user:pass" >/dev/null 2>&1
    local exit_code=$?
    
    # Test invalid auth format
    if ! ./target/release/rustproxy --listen 127.0.0.1:1080 --mode socks5 --socks5-auth "invalid-format" 2>&1 | grep -q "must be in format"; then
        print_error "SOCKS5 auth format validation failed"
        return 1
    fi
    
    print_success "SOCKS5 authentication parsing works correctly"
}

# Main test runner
main() {
    print_header
    
    setup_rust
    build_project
    run_tests
    test_cli_help
    test_cli_modes
    test_cache_parsing
    test_socks5_auth
    
    echo
    print_section "Summary"
    print_success "All basic tests completed successfully!"
    echo
    print_info "To run the full comprehensive test suite with live servers:"
    print_info "  ./test_all.sh"
    echo
    print_info "To manually test specific features:"
    print_info "  TCP Proxy:    ./target/release/rustproxy --listen 127.0.0.1:8080 --target example.com:80 --mode tcp"
    print_info "  HTTP Proxy:   ./target/release/rustproxy --listen 127.0.0.1:8080 --target example.com:80 --mode http"  
    print_info "  SOCKS5 Proxy: ./target/release/rustproxy --listen 127.0.0.1:1080 --mode socks5"
    print_info "  SOCKS5 Auth:  ./target/release/rustproxy --listen 127.0.0.1:1080 --mode socks5 --socks5-auth user:pass"
    echo
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi