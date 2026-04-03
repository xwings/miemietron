# Release Process

## How It Works

Pushing a `v*` tag triggers `.github/workflows/release.yml` which automatically:

1. Cross-compiles release binaries for all 3 targets
2. Generates SHA256 checksums for each binary
3. Creates a GitHub Release with auto-generated notes
4. Attaches binaries:
   - `miemietron-v{VERSION}-x86_64-unknown-linux-musl`
   - `miemietron-v{VERSION}-aarch64-unknown-linux-musl`
   - `miemietron-v{VERSION}-armv7-unknown-linux-musleabihf`

## Release

```bash
# 1. Bump version in Cargo.toml
# 2. Commit
git add -A
git commit -m "v0.2.0: description of changes"

# 3. Tag and push
git tag v0.2.0
git push origin main --tags
```

## Manual Build (no CI)

```bash
# Native
cargo build --release

# Cross-compile
cargo install cross --git https://github.com/cross-rs/cross
cross build --release --target aarch64-unknown-linux-musl
cross build --release --target armv7-unknown-linux-musleabihf
cross build --release --target x86_64-unknown-linux-musl
```

Binaries end up in `target/{triple}/release/miemietron`.
