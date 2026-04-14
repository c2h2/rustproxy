#!/usr/bin/env bash
# RustProxy installer — fetches the latest release binary for this host
# and drops `rustproxy` into the current directory (or $INSTALL_DIR).
#
#   curl -fsSL https://raw.githubusercontent.com/c2h2/rustproxy/master/scripts/install.sh | bash
#
# Override install location:
#   curl -fsSL ...install.sh | INSTALL_DIR=/usr/local/bin bash
#
# Pin a specific tag (otherwise: latest):
#   curl -fsSL ...install.sh | VERSION=v1.0.1 bash

set -euo pipefail

REPO="${REPO:-c2h2/rustproxy}"
INSTALL_DIR="${INSTALL_DIR:-$PWD}"
VERSION="${VERSION:-latest}"

os=$(uname -s)
arch=$(uname -m)

case "$os/$arch" in
    Linux/x86_64 | Linux/amd64)
        asset="rustproxy-linux-amd64.tar.gz"
        archive=tar.gz
        ;;
    Linux/aarch64 | Linux/arm64)
        # musl is statically linked → portable across glibc versions
        asset="rustproxy-linux-arm64-musl.tar.gz"
        archive=tar.gz
        ;;
    Darwin/arm64 | Darwin/aarch64)
        asset="rustproxy-macos-arm64.zip"
        archive=zip
        ;;
    *)
        echo "rustproxy: unsupported platform $os/$arch" >&2
        echo "Available builds: linux-amd64, linux-arm64, macos-arm64" >&2
        exit 1
        ;;
esac

if [ "$VERSION" = "latest" ]; then
    url="https://github.com/${REPO}/releases/latest/download/${asset}"
else
    url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
fi

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fL --progress-bar "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q --show-progress "$1" -O "$2"; }
else
    echo "rustproxy: need curl or wget" >&2
    exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "rustproxy: downloading $asset ($VERSION)"
echo "  from $url"
fetch "$url" "$tmp/$asset"

echo "rustproxy: extracting"
case "$archive" in
    tar.gz) tar -xzf "$tmp/$asset" -C "$tmp" ;;
    zip)
        if ! command -v unzip >/dev/null 2>&1; then
            echo "rustproxy: unzip required to extract macOS archive" >&2
            exit 1
        fi
        unzip -q "$tmp/$asset" -d "$tmp"
        ;;
esac

if [ ! -f "$tmp/rustproxy" ]; then
    echo "rustproxy: archive did not contain expected binary" >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"
mv -f "$tmp/rustproxy" "$INSTALL_DIR/rustproxy"
chmod +x "$INSTALL_DIR/rustproxy"

echo "rustproxy: installed -> $INSTALL_DIR/rustproxy"
