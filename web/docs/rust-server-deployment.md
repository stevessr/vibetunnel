# Rust Server Deployment Guide

This guide covers building, packaging, and deploying the Rust server runtime in `web/rust-server` for VibeTunnel.

## Scope

- Runtime binary: `web/rust-server` (`vibetunnel-rs`)
- Web build/dev scripts that select Rust mode
- npm packaging path for Rust runtime
- macOS app bundle integration expectations

This document is for deployment and release workflow only; protocol/API parity work is tracked separately.

## Runtime selection model

Rust runtime is selected by either:

- `VIBETUNNEL_USE_RUST_SERVER=1`
- `VIBETUNNEL_USE_RUST_SERVER=true`
- `--rust-server` flag on relevant build/dev scripts

Selection logic exists in:

- `web/scripts/dev.js`
- `web/scripts/build.js`
- `web/scripts/build-npm.js`

## Local development (Rust runtime)

From `web/`:

```bash
pnpm run dev -- --rust-server
```

Equivalent env-based form:

```bash
VIBETUNNEL_USE_RUST_SERVER=1 pnpm run dev
```

Behavior in Rust mode:

- client bundles/CSS/assets are still watched by existing JS tooling
- server process is started by Cargo:
  - `cargo run --manifest-path rust-server/Cargo.toml -- --no-auth ...`
- server CLI args after `--` are passed through to Rust runtime

## Production build (Rust runtime)

From `web/`:

```bash
pnpm run build:rust
```

This resolves to:

- `VIBETUNNEL_USE_RUST_SERVER=1 node scripts/build.js --rust-server`

Build behavior in Rust mode (`web/scripts/build.js`):

1. Build web assets (same as TS mode)
2. Build Rust binary:
   - `cargo build --release --manifest-path rust-server/Cargo.toml`
3. Copy binary to:
   - `web/native/vibetunnel-rs`
4. Continue forwarder build flow
5. Skip Node SEA build in Rust mode

Expected artifact after success:

- `web/native/vibetunnel-rs` (mode `755`)

## CI build (Rust runtime)

From `web/`:

```bash
pnpm run build:ci:rust
```

This routes Rust runtime selection through CI build script by setting `VIBETUNNEL_USE_RUST_SERVER=1` and `--rust-server`.

## npm package build (Rust runtime)

From `web/`:

```bash
pnpm run build:npm:rust
```

Behavior in Rust mode (`web/scripts/build-npm.js`):

1. Runs Rust-aware standard build
2. Copies runtime payload into `dist-npm/`:
   - `native/vibetunnel-rs` -> `dist-npm/lib/vibetunnel-rs`
   - `rust-server/fixtures` -> `dist-npm/lib/rust-fixtures`
3. Sets package main to:
   - `lib/vibetunnel-rs`
4. Rewrites `dist-npm/bin/vibetunnel` wrapper to execute Rust binary directly

Resulting npm package launches Rust runtime via wrapper script.

## macOS app integration contract

macOS runtime launch logic is in:

- `mac/VibeTunnel/Core/Services/BunServer.swift`

Current behavior:

1. Prefer bundled `vibetunnel-rs`
2. Fallback to bundled `vibetunnel` if Rust binary is absent
3. Pass same core CLI flags (port/bind/auth/local bypass/tailscale)
4. Set `BUILD_PUBLIC_PATH` so server can find static frontend assets in app bundle

Deployment requirement for macOS packaging:

- App bundle must include `vibetunnel-rs` with executable permissions
- `Resources/web/public` must be present and consistent with built frontend assets

## Required environment and dependencies

- Rust toolchain available in build environment
- Cargo available on PATH
- Node/pnpm toolchain for web asset pipeline
- Existing project prerequisites for native forwarder build

No additional runtime dependency manager is needed for `vibetunnel-rs` binary itself.

## Deployment helper commands (copy/paste)

### 1) Preflight environment check

```bash
cd web
rustc --version
cargo --version
node --version
pnpm --version
```

### 2) Build + binary verification

```bash
cd web
cargo test --manifest-path rust-server/Cargo.toml
pnpm run build:rust

# Binary exists and is executable
[ -x native/vibetunnel-rs ]

# Basic artifact inspection
ls -lh native/vibetunnel-rs
file native/vibetunnel-rs
sha256sum native/vibetunnel-rs || shasum -a 256 native/vibetunnel-rs
```

### 3) Runtime smoke checks (against a running server)

```bash
# Health and status
curl -sSf http://127.0.0.1:4020/api/health
curl -sSf http://127.0.0.1:4020/api/server/status

# Example API sanity checks
curl -sSf "http://127.0.0.1:4020/api/sessions"
curl -sSf "http://127.0.0.1:4020/api/multiplexer/status"
```

### 4) npm Rust package payload verification

```bash
cd web
pnpm run build:npm:rust

# Required payloads
[ -f dist-npm/lib/vibetunnel-rs ]
[ -d dist-npm/lib/rust-fixtures ]
[ -f dist-npm/bin/vibetunnel ]
```

### 5) macOS bundle verification hints

Validate that packaged app resources contain:

- `Resources/vibetunnel-rs` (or project-specific embedded location) with executable bit
- `Resources/web/public` frontend assets

Use app bundle inspection commands as needed during release validation.

## Deployment checklist

Before cutover to Rust default, verify all of the following:

1. `web/rust-server` tests pass:
   - `cargo test` in `web/rust-server`
2. Rust mode build succeeds:
   - `pnpm run build:rust`
3. Rust binary exists and is executable:
   - `web/native/vibetunnel-rs`
4. npm Rust package path succeeds (if publishing npm):
   - `pnpm run build:npm:rust`
5. macOS bundle embeds Rust binary and launches it successfully
6. Frontend bootstrap endpoints required by current client are reachable in Rust mode
7. Protocol fixture tests remain green

## Rollout strategy (single-release parity model)

Use this order:

1. Keep TS runtime as baseline while Rust parity tests run in CI
2. Ship Rust-capable builds behind runtime selection flag
3. Validate macOS bundled launch and npm packaging in Rust mode
4. When parity gates are green, switch default runtime to Rust
5. Remove obsolete TS runtime path only after cutover validation

## Troubleshooting

### Rust binary not found during build

Check:

- `cargo build --release --manifest-path rust-server/Cargo.toml` succeeds
- output exists at `web/rust-server/target/release/vibetunnel-rs`
- copy step produced `web/native/vibetunnel-rs`

### macOS app still launches old runtime

Check bundle contents and launch logs:

- `vibetunnel-rs` present in app Resources
- executable bit set
- logs show Rust binary path selected in `BunServer.swift`

### Runtime starts but UI fails to initialize

Check:

- `BUILD_PUBLIC_PATH` points to valid `web/public` bundle in app resources
- required `/api/*` bootstrap endpoints are implemented in Rust runtime
- auth mode and local bypass token flags are passed consistently

## Key file references

- `web/scripts/dev.js`
- `web/scripts/build.js`
- `web/scripts/build-npm.js`
- `web/package.json`
- `web/rust-server/Cargo.toml`
- `web/rust-server/src/main.rs`
- `mac/VibeTunnel/Core/Services/BunServer.swift`
