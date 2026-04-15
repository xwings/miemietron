# Build Guide

## Quick Start (native, dynamically linked)

```bash
cargo build --release
# Binary: target/release/miemietron (dynamically linked, won't work on OpenWrt)
```

## Static Binary for x86_64 (OpenWrt / deployment)

**This is what you need for OpenWrt and any musl-based system.**

```bash
# 1. Install musl target
rustup target add x86_64-unknown-linux-musl

# 2. Install musl toolchain (pick your distro)
# Arch Linux:
sudo pacman -S musl

# Ubuntu/Debian:
sudo apt install musl-tools

# 3. Build static binary
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-musl

# 4. Verify it's static
file target/x86_64-unknown-linux-musl/release/miemietron
# Should say: "static-pie linked" or "statically linked"
# Must NOT say: "dynamically linked"

# 5. Binary is here:
ls -lh target/x86_64-unknown-linux-musl/release/miemietron
```

## Static Binary for ARM64 (aarch64 routers, RPi 3/4/5)

```bash
# Using cross (no local toolchain needed — builds in Docker)
cross build --release --target aarch64-unknown-linux-musl
```

## Install cross (for ARM builds)

```bash
# Pre-built binary (fast):
curl -sSfL https://github.com/cross-rs/cross/releases/latest/download/cross-x86_64-unknown-linux-musl.tar.gz \
  | sudo tar xz -C /usr/local/bin cross

# Or from source:
cargo install cross --git https://github.com/cross-rs/cross
```

## Deploy to OpenWrt / OpenClash

```bash
# Copy to router (replace with your target arch)
scp target/x86_64-unknown-linux-musl/release/miemietron \
  root@router:/etc/openclash/core/clash_meta

# Set permissions
ssh root@router 'chmod 4755 /etc/openclash/core/clash_meta'

# Verify
ssh root@router '/etc/openclash/core/clash_meta -v'
# Mihomo Meta v0.1.13 linux/x86_64 (miemietron)

# Restart OpenClash
ssh root@router '/etc/init.d/openclash restart'
```

## Release Process

Pushing a `v*` tag triggers GitHub Actions CI which automatically:

1. Cross-compiles static musl binaries for x86_64 and aarch64
2. Generates SHA256 checksums
3. Creates a GitHub Release with binaries attached

```bash
# 1. Bump version in Cargo.toml
# 2. Commit and tag
git checkout main
git merge dev
git tag v0.2.0
git push origin main --tags
```


