# Chatte VPN

Subscription-based VPN client for Windows (Tauri 2 + Rust + React) with a Go
backend. See [ARCHITECTURE.md](ARCHITECTURE.md) for design, decisions, and roadmap.

## Prerequisites

- Node 20+, Go 1.22+, Rust (stable, MSVC), Docker
- [WireGuard for Windows](https://www.wireguard.com/install/) — the client
  drives its tunnel service

## Backend

```powershell
cd server
docker compose up -d --build
# demo subscription (seeded):
curl http://localhost:8080/v1/subscription/chatte-dev-token-1
```

Schema and demo data load automatically on first start (`schema.sql`, `seed.sql`).
The seeded WireGuard configs contain placeholder keys/endpoints — replace them
in `peer_configs` with configs from a real WireGuard server to test traffic.

## Client

```powershell
cd client
npm install
npm run tauri dev   # run the terminal as Administrator
```

Paste `http://localhost:8080/v1/subscription/chatte-dev-token-1` as the
subscription URL. Connect installs the `WireGuardTunnel$Chatte` Windows
service (verify: `sc query WireGuardTunnel$Chatte`); disconnect removes it.

Administrator is required because installing a tunnel service is privileged.
Phase 2 splits a background Windows service so the UI runs unelevated.

## Tests

```powershell
cd server; go test ./...
cd client/src-tauri; cargo test
```
