#!/bin/bash

# Rust Cross-Compilation Script for rustproxy
# Builds for ARM64 (aarch64) and x86_64 architectures

set -e
source "$HOME/.cargo/env"

echo "🦀 Rust Cross-Compilation Script for rustproxy"
echo "=============================================="

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

# Target architectures
TARGETS=(
    "aarch64-unknown-linux-gnu"    # ARM64 Linux
    "x86_64-unknown-linux-gnu"     # x86_64 Linux
)

# Create output directory
OUTPUT_DIR="dist"
mkdir -p "${OUTPUT_DIR}"

echo -e "${YELLOW}📦 Setting up build targets...${NC}"

# Add targets if not already installed
for target in "${TARGETS[@]}"; do
    echo "  Adding target: ${target}"
    rustup target add "${target}" || true
done

echo ""
echo -e "${YELLOW}🔧 Installing cross-compilation dependencies...${NC}"

# Ensure the aarch64 GCC cross-compiler toolchain is installed
if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
    echo "  aarch64-linux-gnu-gcc not found. Installing via apt..."
    sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu || {
        echo -e "${RED}Failed to install aarch64 cross-compiler toolchain.${NC}"
        echo -e "${RED}Please run manually: sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu${NC}"
        exit 1
    }
else
    echo "  aarch64-linux-gnu-gcc found: $(aarch64-linux-gnu-gcc --version | head -1)"
fi

# Configure cargo to use the cross-compiler linker for aarch64
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

echo ""
echo -e "${YELLOW}🏗️  Building for multiple architectures...${NC}"

# Build function
build_target() {
    local target=$1
    local arch_name=""
    
    case $target in
        "aarch64-unknown-linux-gnu")
            arch_name="arm64"
            ;;
        "x86_64-unknown-linux-gnu")
            arch_name="x64"
            ;;
        *)
            arch_name=$target
            ;;
    esac
    
    echo -e "${BLUE}Building for ${arch_name} (${target})...${NC}"

    echo "  Using cargo for compilation..."
    cargo build --release --target "${target}" || {
        echo -e "${RED}Failed to build for ${target}${NC}"
        return 1
    }
    
    # Copy binary to dist folder with architecture suffix
    local binary_name="${PROJECT_NAME}"
    local source_path="target/${target}/release/${binary_name}"
    local dest_path="${OUTPUT_DIR}/${binary_name}-${arch_name}"
    
    if [ -f "${source_path}" ]; then
        cp "${source_path}" "${dest_path}"
        echo -e "${GREEN}  ✓ Binary created: ${dest_path}${NC}"
        
        # Show file info
        ls -lh "${dest_path}"
        file "${dest_path}"
    else
        echo -e "${RED}  ✗ Binary not found at ${source_path}${NC}"
        return 1
    fi
    
    echo ""
}

# Build for each target
SUCCESS_COUNT=0
TOTAL_COUNT=${#TARGETS[@]}

for target in "${TARGETS[@]}"; do
    if build_target "${target}"; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done

echo "=============================================="
echo -e "${BLUE}📊 Build Summary${NC}"
echo -e "Successful builds: ${GREEN}${SUCCESS_COUNT}${NC}/${TOTAL_COUNT}"

if [ -d "${OUTPUT_DIR}" ] && [ "$(ls -A ${OUTPUT_DIR})" ]; then
    echo ""
    echo -e "${YELLOW}📁 Generated binaries in ${OUTPUT_DIR}/:${NC}"
    ls -la "${OUTPUT_DIR}/"
    
    echo ""
    echo -e "${YELLOW}📏 Binary sizes:${NC}"
    du -h "${OUTPUT_DIR}"/*
    
    echo ""
    echo -e "${YELLOW}🔍 Binary details:${NC}"
    for binary in "${OUTPUT_DIR}"/*; do
        if [ -f "$binary" ]; then
            echo "$(basename "$binary"):"
            file "$binary"
            echo ""
        fi
    done
else
    echo -e "${RED}No binaries were generated successfully.${NC}"
    exit 1
fi

echo -e "${GREEN}🎉 Cross-compilation complete!${NC}"

# Optional: Create a simple usage script
cat > "${OUTPUT_DIR}/README.md" << EOF
# ${PROJECT_NAME} Cross-Compiled Binaries

This directory contains cross-compiled binaries for different architectures:

## Binaries

- \`${PROJECT_NAME}-arm64\` - ARM64 Linux binary (aarch64-unknown-linux-gnu)
- \`${PROJECT_NAME}-x64\` - x86_64 Linux binary (x86_64-unknown-linux-gnu)

## Usage

Choose the appropriate binary for your target architecture:

### ARM64 (Apple Silicon, ARM servers, Raspberry Pi, etc.)
\`\`\`bash
./${PROJECT_NAME}-arm64
\`\`\`

### x86_64 (Intel/AMD processors)
\`\`\`bash
./${PROJECT_NAME}-x64
\`\`\`

## Installation

1. Copy the appropriate binary to your target system
2. Make it executable: \`chmod +x ${PROJECT_NAME}-<arch>\`
3. Run it directly or place it in your PATH

## Proxy Configuration

The proxy will start the following services:
- TCP Proxy on port 63900 → 100.87.131.64:9000 (jfk)
- TCP Proxy on port 63901 → 100.81.79.85:9000 (jfk2)  
- TCP Proxy on port 63902 → 100.126.93.69:9000 (jjp)
- TCP Proxy on port 63903 → 100.108.162.97:9000 (jau)
- HTTP Proxy on port 38080

Built with Rust $(rustc --version)
Generated on $(date)
EOF

echo -e "${BLUE}📝 Documentation created: ${OUTPUT_DIR}/README.md${NC}"
echo ""
echo -e "${GREEN}All done! 🚀${NC}"
