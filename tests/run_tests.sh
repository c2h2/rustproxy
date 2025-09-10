#!/bin/bash

# RustProxy Test Runner
# Organizes and runs different test categories

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "🧪 RustProxy Test Suite Runner"
echo "=============================="

# Function to run a test category
run_category() {
    local category="$1"
    local description="$2"
    shift 2
    
    echo ""
    echo "🔧 $category - $description"
    echo "----------------------------------------"
    
    for test in "$@"; do
        if [ -f "tests/$test" ]; then
            echo "   Running: $test"
            ./tests/$test
            echo "   ✅ Completed: $test"
        else
            echo "   ⚠️  Not found: $test"
        fi
    done
}

# Parse command line arguments
case "${1:-all}" in
    "basic")
        run_category "Basic Tests" "Core functionality verification" \
            "test_basic.sh" "test_simple.sh" "test_fast.sh"
        ;;
    
    "dashboard")
        echo "🎯 Starting manager and proxies for dashboard tests..."
        # Ensure manager is running for dashboard tests
        if ! curl -s http://127.0.0.1:8080/api/health > /dev/null 2>&1; then
            echo "   Manager not running. Please start with:"
            echo "   ./target/release/rustproxy --manager --listen 127.0.0.1:8080"
            exit 1
        fi
        
        run_category "Dashboard Tests" "Dashboard performance and accuracy" \
            "test_mbps.sh" "dashboard_stress_test.sh" "final_demo_test.sh"
        ;;
    
    "traffic")
        run_category "Traffic Generation" "High-volume traffic testing" \
            "high_traffic_test.sh" "local_volume_test.sh" "fast_gb_test.sh"
        ;;
    
    "gigabyte")
        echo "⚠️  Warning: Gigabyte tests may take several minutes and require network access"
        read -p "Continue? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            run_category "Gigabyte Tests" "Large-scale data handling" \
                "gigabyte_test.sh" "fast_gb_test.sh"
        fi
        ;;
    
    "build")
        run_category "Build Tests" "Compilation and setup verification" \
            "compile.sh" "setup_limits.sh"
        ;;
    
    "integration")
        run_category "Integration Tests" "End-to-end system testing" \
            "test_integration.sh" "test_all.sh"
        ;;
    
    "demo")
        run_category "Demonstrations" "Feature demonstrations" \
            "demo.sh" "demo_caching.sh"
        ;;
    
    "all")
        echo "🚀 Running comprehensive test suite..."
        echo "Note: Skipping gigabyte tests by default (use 'gigabyte' category to run them)"
        
        $0 basic
        $0 build
        $0 integration
        $0 dashboard
        $0 traffic
        $0 demo
        
        echo ""
        echo "🎉 All test categories completed!"
        echo "   For gigabyte-scale tests, run: $0 gigabyte"
        ;;
    
    "help"|"-h"|"--help")
        echo "Usage: $0 [category]"
        echo ""
        echo "Categories:"
        echo "  basic      - Core functionality tests"
        echo "  dashboard  - Dashboard performance tests"
        echo "  traffic    - Traffic generation tests"
        echo "  gigabyte   - Large-scale data tests (slow)"
        echo "  build      - Build and setup tests"
        echo "  integration- Integration tests"
        echo "  demo       - Feature demonstrations"
        echo "  all        - Run all categories (default)"
        echo "  help       - Show this help"
        echo ""
        echo "Examples:"
        echo "  $0 dashboard  # Test dashboard only"
        echo "  $0 traffic    # Generate test traffic"
        echo "  $0            # Run all tests"
        ;;
    
    *)
        echo "❌ Unknown category: $1"
        echo "Run '$0 help' for available categories"
        exit 1
        ;;
esac

echo ""
echo "✨ Test run completed!"