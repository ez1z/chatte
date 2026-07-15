# Chatte VPN — System Architecture

Commercial-grade VPN client + subscription backend, in the style of Happ VPN.
Client: Windows first. Protocols: WireGuard first, Xray (VLESS/Trojan) second.
We orchestrate battle-tested VPN engines; we never implement a protocol ourselves.

## System overview

```
┌────────────────────────── Windows client ──────────────────────────┐
│  React + TS UI (Tauri webview)                                     │
│      │  invoke() — metadata & state only, never tokens/configs     │
│  Tauri backend (Rust)                                              │
│      ├─ store.rs   → Windows Credential Manager (subscription URL) │
│      ├─ api        → reqwest/rustls → Backend API                  │
│      └─ vpn.rs     → wireguard.exe /installtunnelservice           │
│                          └─ WireGuard tunnel service (Wintun)      │
│                             owns adapter, routes, DNS — system-wide│
└────────────────────────────────────────────────────────────────────┘
                                   │ HTTPS
┌────────────────────────── Backend (Go) ────────────────────────────┐
│  GET /v1/subscription/{token}  →  expiry + servers + configs       │
│  GET /healthz                                                      │
│  PostgreSQL: users, subscriptions, servers, peer_configs           │
└────────────────────────────────────────────────────────────────────┘
                                   │
                    VPN fleet (WireGuard / Xray servers)
```

## Major technical decisions

- **Go backend, stdlib `net/http`** (Go 1.22 method-pattern mux). Static binary,
  trivial Docker image, no framework to maintain. pgx is the only dependency.
- **No Redis in MVP.** Postgres handles this scale. Add Redis when a measurement
  says so, not before.
- **Tauri 2 + React**, not Electron: ~10x smaller memory footprint, Rust process
  boundary between the webview and anything privileged.
- **Secrets never enter the webview.** The subscription URL (which contains the
  token) lives in Windows Credential Manager via the `keyring` crate; WireGuard
  configs are fetched and held in Rust memory. The UI receives only server
  metadata and connection state.
- **WireGuard via the official Windows tunnel service**
  (`wireguard.exe /installtunnelservice`). The WG service owns the Wintun
  adapter, routing table (`AllowedIPs = 0.0.0.0/0` gives system-wide routing —
  browsers, cmd, PowerShell, WSL NAT traffic, everything), DNS, and
  reconnection at the protocol level. Reimplementing any of that is how VPN
  clients get CVEs.
- **Tokens are stored hashed** (SHA-256) server-side. A leaked DB does not leak
  subscriptions.
- **Config distribution, MVP:** pre-rendered per-(subscription, server)
  WireGuard configs stored in `peer_configs`, served over TLS. Automated peer
  provisioning (key generation + pushing peers to WG servers) is Phase 2 — it
  is the genuinely hard part and deserves its own iteration.

## Data model

```
users              id, email, created_at
subscriptions      id, user_id, token_hash (sha256 hex, unique),
                   expires_at, device_limit, revoked
servers            id ('de-01'), name, country, city,
                   protocol ∈ {wireguard, vless, trojan, shadowsocks}, enabled
peer_configs       (subscription_id, server_id) → config text
```

## Security model

| Threat | Mitigation |
|---|---|
| DB leak | token hashes only; configs are per-subscription, revocable |
| Token guessing | 256-bit random tokens; per-IP rate limit on the API |
| Local credential theft | Credential Manager (DPAPI) for token; WG conf on disk only while connected, deleted on disconnect |
| MITM to backend | TLS via rustls, system roots; no cert-check bypass anywhere |
| Replay / rotation | Phase 3: short-lived signed config URLs, device auth |

## Repository structure

```
server/   Go API + schema + docker-compose (Postgres 16 + API)
client/   Tauri 2 app — src/ (React UI), src-tauri/ (Rust core)
```

## Roadmap

**Phase 1 (this codebase):** backend API, subscription system, Windows client,
WireGuard connect/disconnect, server list, status + public IP.

**Phase 2:** Xray-core sidecar (VLESS/Trojan) driven by the same Rust
controller; automated WG peer provisioning; tray + autostart; reconnect after
sleep/wake; auto-update (Tauri updater); server health checks feeding the
`servers` table; Windows service broker so the UI runs unelevated.

**Phase 3:** kill switch (WFP firewall rules), DNS-leak protection, device
management/limits enforcement, billing, analytics, code signing + CI/CD.

## Known MVP ceilings (marked `ponytail:` in code)

- App must run elevated (tunnel service install needs admin) → service broker in Phase 2.
- WG conf exists on disk while a tunnel is up → DPAPI-encrypted conf + ACL hardening later.
- Rate limiter is in-memory per-instance → move behind a real gateway when horizontally scaled.
