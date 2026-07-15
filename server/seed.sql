-- Demo data. Token (plaintext, dev only): chatte-dev-token-1
-- sha256('chatte-dev-token-1') = below hash.
INSERT INTO users (email) VALUES ('demo@chatte.dev') ON CONFLICT DO NOTHING;

INSERT INTO subscriptions (user_id, token_hash, expires_at)
SELECT id, 'b793c5e9b6efd2b09395698be0af1dfbc71a1dc5b47a342f8997feb8260e34a8', '2026-12-31T00:00:00Z'
FROM users WHERE email = 'demo@chatte.dev'
ON CONFLICT (token_hash) DO NOTHING;

INSERT INTO servers (id, name, country, city, protocol) VALUES
    ('de-01', 'Germany #1', 'DE', 'Frankfurt', 'wireguard'),
    ('nl-01', 'Netherlands #1', 'NL', 'Amsterdam', 'wireguard')
ON CONFLICT (id) DO NOTHING;

-- Placeholder WG configs; replace Endpoint/keys with a real server to test traffic.
INSERT INTO peer_configs (subscription_id, server_id, config)
SELECT s.id, srv.id,
'[Interface]
PrivateKey = cGxhY2Vob2xkZXIta2V5LXJlcGxhY2UtbWUtMDAwMDA=
Address = 10.66.66.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = c2VydmVyLXB1YmxpYy1rZXktcmVwbGFjZS1tZS0wMDA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ' || srv.id || '.vpn.example.com:51820
PersistentKeepalive = 25'
FROM subscriptions s CROSS JOIN servers srv
ON CONFLICT DO NOTHING;
