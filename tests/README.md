# RustProxy Test Suite

This directory contains comprehensive tests for the RustProxy system, including dashboard performance tests and traffic generation scripts.

## Test Categories

### 🚀 Basic Tests
- `test_basic.sh` - Basic proxy functionality tests
- `test_simple.sh` - Simple integration tests
- `test_fast.sh` - Quick functionality verification

### 📊 Dashboard Tests
- `dashboard_stress_test.sh` - Dashboard performance under load
- `final_demo_test.sh` - Complete dashboard demonstration
- `test_mbps.sh` - Mbps calculation verification

### 🔥 Traffic Generation
- `gigabyte_test.sh` - Large-scale traffic test (100 x 10MB files)
- `fast_gb_test.sh` - Rapid small-chunk traffic test (1000 x 1MB files)  
- `high_traffic_test.sh` - Continuous high-bandwidth traffic
- `local_volume_test.sh` - Burst traffic simulation

### 🏗️ Build & Setup
- `compile.sh` - Standard build script
- `compile-simple.sh` - Simple build configuration
- `compile-multi.sh` - Multi-target build
- `setup_limits.sh` - System limits configuration

### 🧪 Integration Tests
- `test_all.sh` - Comprehensive test suite
- `test_integration.sh` - Integration test runner
- `test_manager.sh` - Manager system tests
- `test_proxy.sh` - Proxy functionality tests
- `test_stress.sh` - Stress testing
- `integration_tests.rs` - Rust integration tests

### 🎬 Demos
- `demo.sh` - Basic demonstration
- `demo_caching.sh` - Caching feature demo

## Quick Start

### Run Dashboard Tests
```bash
# Start manager and proxies first
./tests/test_basic.sh

# Test dashboard performance
./tests/dashboard_stress_test.sh

# Generate demo traffic
./tests/final_demo_test.sh
```

### Traffic Testing
```bash
# Quick Mbps verification
./tests/test_mbps.sh

# High-volume testing
./tests/gigabyte_test.sh

# Burst traffic simulation
./tests/local_volume_test.sh
```

### Full Test Suite
```bash
# Run all tests
./tests/test_all.sh
```

## Dashboard Fixes Tested

The tests in this suite verify the following dashboard improvements:

✅ **Browser Crash Prevention**: Rate-limited updates and connection management  
✅ **Accurate Mbps Calculations**: Real-time bandwidth instead of cumulative bytes  
✅ **Performance Optimization**: Throttling and efficient DOM updates  
✅ **Memory Management**: Proper cleanup and resource management  
✅ **WebSocket Stability**: Exponential backoff reconnection  
✅ **Large Data Handling**: Gigabyte-scale data processing  

## Test Results

All tests verify that the dashboard:
- Displays accurate real-time Mbps
- Handles high-volume traffic without crashes
- Shows properly formatted data (GB/MB/KB)
- Maintains responsive WebSocket connections
- Provides stable performance under load

Visit `http://127.0.0.1:8080/` during any test to see the live dashboard in action.