# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Scope
This file applies to the `web/` workspace (TypeScript server/client plus optional Rust runtime).

## Required workflow constraints
- The user usually has dev/watch processes running already.
  - Do not start or restart the server unless explicitly asked.
  - Do not run build commands unless explicitly asked.
- Do not run tests unless explicitly asked.
- Do not install new packages without explicit approval.
  - Do not run `pnpm add` / `npm install` for new deps.
  - Do not modify `package.json` or lockfiles for dependency changes unless requested.
- Keep references clickable in `path/to/file:line` or `path/to/file:start-end` format.

## Common commands
Use `pnpm` from `web/`.

### Development
- `pnpm install`
- `pnpm run dev` (full dev flow)
- `pnpm run dev:mobile` (binds `0.0.0.0:4021` for external device testing)
- `pnpm run dev:server` (TS server only)
- `pnpm run dev:server:rust` (Rust server only)
- `pnpm run dev:client` (client-only mode)

### Quality checks
- `pnpm run check` (format check + lint + type-aware lint + typecheck + vt script test)
- `pnpm run check:fix` (auto-fix formatting/lint then re-check)

### Tests (run only when asked)
- `pnpm run test`
- `pnpm run test:server`
- `pnpm run test:client`
- Single Vitest file: `pnpm exec vitest run src/test/unit/ws-v3.test.ts`
- Single Vitest test name: `pnpm exec vitest run src/test/unit/ws-v3.test.ts -t "encode"`
- `pnpm run test:e2e`
- Single Playwright spec: `pnpm exec playwright test src/test/playwright/specs/smoke.spec.ts`
- Single Playwright test name: `pnpm exec playwright test src/test/playwright/specs/smoke.spec.ts -g "session"`
- Rust runtime tests: `cargo test --manifest-path rust-server/Cargo.toml`

### Build/reference commands (only when asked)
- `pnpm run build`
- `pnpm run build:rust`
- `pnpm run build:npm`
- `pnpm run build:npm:rust`

## Architecture map (big picture)

### Entry points and runtime selection
- CLI entry and command dispatch: `src/cli.ts:292-327`
  - `vibetunnel fwd/status/follow/unfollow/git-event/systemd` are handled here.
  - Default path starts server via `startVibeTunnelServer()` (`src/cli.ts:281-287`).
- Main server assembly: `src/server/server.ts:452-1350` (`createApp`).
- Server bootstrap: `src/server/server.ts:1628-1656` (`startVibeTunnelServer`).
- Client bootstrap: `src/client/app-entry.ts:1-8`.
- Main app shell: `src/client/app.ts:49-74` (`<vibetunnel-app>` with top-level state).
- Rust runtime exists as alternative server at `rust-server/src/main.rs` and is selected by `VIBETUNNEL_USE_RUST_SERVER=1` / `--rust-server` in scripts.

### Server composition
- `createApp` wires core services:
  - `PtyManager` + `SessionManager` for PTY/session lifecycle and persistence.
  - `TerminalManager` for Ghostty-based headless terminal snapshots.
  - `CastOutputHub` + `GitStatusHub` for event/output fanout.
  - `WsV3Hub` for `/ws` binary multiplexed transport.
- Route mounting happens in `src/server/server.ts:1061-1153` using route modules under `src/server/routes/`.
- Static/SPA behavior is in `src/server/server.ts:745-851` and `src/server/server.ts:1318-1348`.

### PTY/session data flow
1. Session creation and PTY process management: `src/server/pty/pty-manager.ts:123-161`.
2. Session persistence under control dir (`~/.vibetunnel/control/...`): `src/server/pty/session-manager.ts:16-24`, `src/server/pty/session-manager.ts:146-169`.
3. WebSocket v3 framing contract: `src/shared/ws-v3.ts:1-37`.
4. WS v3 server hub handles subscribe/input/resize/kill and emits stdout/snapshot/event frames: `src/server/services/ws-v3-hub.ts:57-192`.
5. Client WebSocket multiplexer with reconnect + per-session subscriptions: `src/client/services/terminal-socket-client.ts:50-157`.

### API shape
- Session/API routes are modularized (auth/sessions/git/filesystem/worktrees/multiplexer/tmux/etc.).
- A representative aggregation point is `src/server/routes/sessions.ts:48-240`.
- `/ws` upgrade/auth routing is in `src/server/server.ts:1175-1316`.

### Client structure
- `src/client/app.ts` is the orchestration layer for auth/session/file-browser views.
- UI is componentized under `src/client/components/*`.
- Service layer under `src/client/services/*` handles auth, server events, WebSocket terminal transport, and push notifications.

## Important project-specific conventions
- Use `Z_INDEX` constants from `src/client/utils/constants.ts` instead of hardcoded z-index values.
- Prefer stable element IDs/data-testid for testability on interactive UI.
- Do not add `"vt": "./bin/vt"` to `package.json`/`package.npm.json` `bin` section.

## Key docs to consult
- Architecture/API overview: `docs/spec.md`
- IPC framing for Unix socket control channel: `docs/socket-protocol.md`
- Playwright patterns used in this repo: `docs/playwright-testing.md`
- Rust runtime build/deploy flow: `docs/rust-server-deployment.md`
