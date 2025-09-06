#!/bin/bash

# Multi-Architecture Rust Compilation Script for rustproxy
# Supports native, cross-compilation, and Docker-based builds

set -e

echo "🦀 Multi-Architecture Rust Compilation Script for rustproxy"
echo "==========================================================="

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Project info
PROJECT_NAME="rustproxy"
VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

echo -e "${BLUE}Project: ${PROJECT_NAME} v${VERSION}${NC}"
echo ""

# Detect current architecture
CURRENT_ARCH=$(uname -m)
echo -e "${BLUE}Current architecture: ${CURRENT_ARCH}${NC}"

# Target architectures
declare -A TARGETS
TARGETS[arm64]="aarch64-unknown-linux-gnu"
TARGETS[x64]="x86_64-unknown-linux-gnu"

# Create output directory
OUTPUT_DIR="dist"
mkdir -p "${OUTPUT_DIR}"

echo ""
echo -e "${YELLOW}🎯 Available build modes:${NC}"
echo "1. Native build (current architecture only)"
echo "2. Cross-compilation (requires toolchains)"
echo "3. Docker-based cross-compilation (requires Docker)"
echo "4. All available methods"

# Function to build native
build_native() {
    echo -e "${BLUE}Building native binary...${NC}"
    
    cargo build --release || {
        echo -e "${RED}Failed to build native binary${NC}"
        return 1
    }
    
    local arch_name=""
    case $CURRENT_ARCH in
        aarch64|arm64)
            arch_name="arm64"
            ;;
        x86_64|amd64)
            arch_name="x64"
            ;;
        *)
            arch_name="native-${CURRENT_ARCH}"
            ;;
    esac
    
    cp "target/release/${PROJECT_NAME}" "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}"
    echo -e "${GREEN}✓ Native binary created: ${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}${NC}"
    
    ls -lh "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}"
    file "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}" 2>/dev/null || echo "  (file command not available)"
    echo ""
    return 0
}

# Function to try cross compilation
try_cross_compilation() {
    local target=$1
    local arch_name=$2
    
    echo -e "${BLUE}Attempting cross-compilation for ${arch_name} (${target})...${NC}"
    
    # Add target
    rustup target add "${target}" || {
        echo -e "${RED}Failed to add target ${target}${NC}"
        return 1
    }
    
    # Try building
    if cargo build --release --target "${target}" 2>/dev/null; then
        cp "target/${target}/release/${PROJECT_NAME}" "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}"
        echo -e "${GREEN}✓ Cross-compiled binary created: ${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}${NC}"
        
        ls -lh "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}"
        file "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}" 2>/dev/null || echo "  (file command not available)"
        echo ""
        return 0
    else
        echo -e "${YELLOW}⚠ Cross-compilation failed for ${arch_name}${NC}"
        echo "  This is normal if you don't have the cross-compilation toolchain installed"
        return 1
    fi
}

# Function to try Docker-based cross compilation
try_docker_cross() {
    local target=$1
    local arch_name=$2
    
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}Docker not available for ${arch_name}${NC}"
        return 1
    fi
    
    if ! docker version &> /dev/null; then
        echo -e "${YELLOW}Docker not accessible for ${arch_name}${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Attempting Docker-based cross-compilation for ${arch_name}...${NC}"
    
    if command -v cross &> /dev/null || cargo install cross &> /dev/null; then
        if cross build --release --target "${target}" 2>/dev/null; then
            cp "target/${target}/release/${PROJECT_NAME}" "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}"
            echo -e "${GREEN}✓ Docker cross-compiled binary created: ${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}${NC}"
            
            ls -lh "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}"
            file "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}" 2>/dev/null || echo "  (file command not available)"
            echo ""
            return 0
        fi
    fi
    
    echo -e "${YELLOW}⚠ Docker cross-compilation failed for ${arch_name}${NC}"
    return 1
}

# Function to build for specific architecture
build_for_arch() {
    local arch_name=$1
    local target=${TARGETS[$arch_name]}
    
    if [ -z "$target" ]; then
        echo -e "${RED}Unknown architecture: ${arch_name}${NC}"
        return 1
    fi
    
    # Skip if file already exists
    if [ -f "${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}" ]; then
        echo -e "${GREEN}✓ Binary already exists: ${OUTPUT_DIR}/${PROJECT_NAME}-${arch_name}${NC}"
        return 0
    fi
    
    # For current architecture, prefer native build
    case $CURRENT_ARCH in
        aarch64|arm64)
            if [ "$arch_name" = "arm64" ]; then
                build_native && return 0
            fi
            ;;
        x86_64|amd64)
            if [ "$arch_name" = "x64" ]; then
                build_native && return 0
            fi
            ;;
    esac
    
    # Try cross-compilation methods
    try_cross_compilation "$target" "$arch_name" && return 0
    try_docker_cross "$target" "$arch_name" && return 0
    
    echo -e "${RED}✗ Failed to build for ${arch_name}${NC}"
    return 1
}

# Parse command line arguments
MODE=${1:-"4"}

case $MODE in
    "1"|"native")
        echo -e "${YELLOW}Building native binary only...${NC}"
        build_native
        ;;
    "2"|"cross")
        echo -e "${YELLOW}Attempting cross-compilation for all architectures...${NC}"
        for arch in "${!TARGETS[@]}"; do
            build_for_arch "$arch"
        done
        ;;
    "3"|"docker")
        echo -e "${YELLOW}Attempting Docker-based cross-compilation...${NC}"
        for arch in "${!TARGETS[@]}"; do
            try_docker_cross "${TARGETS[$arch]}" "$arch"
        done
        ;;
    "4"|"all"|*)
        echo -e "${YELLOW}Trying all available methods...${NC}"
        echo ""
        
        # Always build native first
        build_native
        
        # Try other architectures
        for arch in "${!TARGETS[@]}"; do
            # Skip current architecture (already built native)
            case $CURRENT_ARCH in
                aarch64|arm64)
                    [ "$arch" = "arm64" ] && continue
                    ;;
                x86_64|amd64)
                    [ "$arch" = "x64" ] && continue
                    ;;
            esac
            
            build_for_arch "$arch"
        done
        ;;
esac

echo "=============================================="
echo -e "${BLUE}📊 Build Summary${NC}"

if [ -d "${OUTPUT_DIR}" ] && [ "$(ls -A ${OUTPUT_DIR} 2>/dev/null)" ]; then
    BINARY_COUNT=$(ls -1 "${OUTPUT_DIR}" | wc -l)
    echo -e "Generated binaries: ${GREEN}${BINARY_COUNT}${NC}"
    
    echo ""
    echo -e "${YELLOW}📁 Generated binaries in ${OUTPUT_DIR}/:${NC}"
    ls -la "${OUTPUT_DIR}/"
    
    echo ""
    echo -e "${YELLOW}📏 Binary sizes:${NC}"
    du -h "${OUTPUT_DIR}"/* 2>/dev/null || echo "No binaries found"
    
    echo ""
    echo -e "${YELLOW}🔍 Binary details:${NC}"
    for binary in "${OUTPUT_DIR}"/*; do
        if [ -f "$binary" ]; then
            echo "$(basename "$binary"):"
            file "$binary" 2>/dev/null || echo "  (file command not available)"
            echo ""
        fi
    done
    
    # Create README
    cat > "${OUTPUT_DIR}/README.md" << EOF
# ${PROJECT_NAME} Multi-Architecture Binaries

This directory contains compiled binaries for different architectures:

## Available Binaries

EOF
    
    for binary in "${OUTPUT_DIR}"/*; do
        if [ -f "$binary" ] && [ "$(basename "$binary")" != "README.md" ]; then
            binary_name=$(basename "$binary")
            echo "- \`${binary_name}\` - $(file "$binary" 2>/dev/null | cut -d: -f2- || echo "Binary file")" >> "${OUTPUT_DIR}/README.md"
        fi
    done
    
    cat >> "${OUTPUT_DIR}/README.md" << EOF

## Usage

Choose the appropriate binary for your target architecture and run:

\`\`\`bash
chmod +x ${PROJECT_NAME}-<arch>
./${PROJECT_NAME}-<arch>
\`\`\`

## Proxy Configuration

The proxy will start the following services:
- TCP Proxy on port 63900 → 100.87.131.64:9000 (jfk)
- TCP Proxy on port 63901 → 100.81.79.85:9000 (jfk2)  
- TCP Proxy on port 63902 → 100.126.93.69:9000 (jjp)
- TCP Proxy on port 63903 → 100.108.162.97:9000 (jau)
- HTTP Proxy on port 38080

Built with Rust $(rustc --version 2>/dev/null || echo "version unknown")
Generated on $(date)
EOF

    echo -e "${BLUE}📝 Documentation created: ${OUTPUT_DIR}/README.md${NC}"
else
    echo -e "${RED}No binaries were generated successfully.${NC}"
    echo ""
    echo -e "${YELLOW}💡 Troubleshooting tips:${NC}"
    echo "1. For cross-compilation, install the target toolchain:"
    echo "   rustup target add <target-triple>"
    echo "2. For Docker-based builds, ensure Docker is running"
    echo "3. Consider building natively on each target platform"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 Compilation complete! 🚀${NC}"