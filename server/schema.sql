CREATE TABLE IF NOT EXISTS users (
    id         BIGSERIAL PRIMARY KEY,
    email      TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id),
    token_hash   TEXT UNIQUE NOT NULL, -- sha256 hex of the subscription token
    expires_at   TIMESTAMPTZ NOT NULL,
    device_limit INT NOT NULL DEFAULT 3,
    revoked      BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS servers (
    id       TEXT PRIMARY KEY, -- e.g. 'de-01'
    name     TEXT NOT NULL,
    country  TEXT NOT NULL,
    city     TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL CHECK (protocol IN ('wireguard', 'vless', 'trojan', 'shadowsocks')),
    enabled  BOOLEAN NOT NULL DEFAULT true
);

-- Pre-rendered client config per (subscription, server).
-- ponytail: provisioned offline for MVP; automated WG peer provisioning is Phase 2.
CREATE TABLE IF NOT EXISTS peer_configs (
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    server_id       TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    config          TEXT NOT NULL,
    PRIMARY KEY (subscription_id, server_id)
);
