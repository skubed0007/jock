#!/bin/bash

set -e

# Create output directories
mkdir -p bin/release/linux bin/release/windows

# Build for Linux
echo "Building for Linux..."
cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/jock bin/release/linux/jock

# Build for Windows
echo "Building for Windows..."
cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/jock.exe bin/release/windows/jock.exe

echo "Build completed successfully!"
