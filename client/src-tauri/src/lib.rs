//! Tauri commands. Rule: WireGuard configs and the subscription token stay in
//! this process; the webview only ever sees server metadata and status.

mod singbox;
mod store;
mod vpn;

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

#[derive(Clone, Deserialize)]
struct SubscriptionPayload {
    #[serde(default)]
    expires: Option<String>,
    servers: Vec<ServerConfig>,
}

#[derive(Clone, Deserialize)]
struct ServerConfig {
    id: String,
    name: String,
    country: String,
    city: String,
    protocol: String,
    config: String,
}

/// What the UI is allowed to see — no `config` field.
#[derive(Clone, Serialize)]
struct ServerInfo {
    id: String,
    name: String,
    country: String,
    city: String,
    protocol: String,
}

#[derive(Serialize)]
struct AppStatus {
    has_subscription: bool,
    expires: Option<String>,
    servers: Vec<ServerInfo>,
    connected: bool,
    connected_server: Option<String>,
}

#[derive(Default)]
struct AppState {
    expires: Option<String>,
    servers: Vec<ServerConfig>,
    connected_server: Option<String>,
}

type Shared = Mutex<AppState>;

fn to_info(servers: &[ServerConfig]) -> Vec<ServerInfo> {
    servers
        .iter()
        .map(|s| ServerInfo {
            id: s.id.clone(),
            name: s.name.clone(),
            country: s.country.clone(),
            city: s.city.clone(),
            protocol: s.protocol.clone(),
        })
        .collect()
}

fn parse_sub_url(url: &str) -> Result<reqwest::Url, String> {
    let u: reqwest::Url = url.trim().parse().map_err(|_| "invalid URL".to_string())?;
    match u.scheme() {
        "https" => Ok(u),
        // ponytail: http allowed for localhost dev only; TLS everywhere else.
        "http" if matches!(u.host_str(), Some("localhost" | "127.0.0.1")) => Ok(u),
        _ => Err("subscription URL must be https".into()),
    }
}

async fn fetch_subscription(url: &str) -> Result<SubscriptionPayload, String> {
    let parsed = parse_sub_url(url)?;
    let resp = reqwest::get(parsed).await.map_err(|e| e.to_string())?;
    match resp.status().as_u16() {
        200 => {}
        403 => return Err("subscription expired".into()),
        404 => return Err("subscription not found — check the URL".into()),
        s => return Err(format!("server error ({s})")),
    }
    let body = resp.text().await.map_err(|e| format!("bad response: {e}"))?;
    // Chatte's own backend serves our JSON shape; anything else we treat as a
    // Marzban panel and fetch its sing-box format.
    if let Ok(p) = serde_json::from_str::<SubscriptionPayload>(&body) {
        return Ok(p);
    }
    fetch_marzban(url).await
}

/// Build the Marzban sing-box subscription URL from a pasted sub link.
/// Happ-style links can domain-front: the base host is a decoy and the real
/// host rides in the fragment (`#?...&host=real.example`). We honour `host=`.
/// ponytail: `resolve-address` / DNS-level fronting is not implemented.
fn marzban_singbox_url(input: &str) -> Result<String, String> {
    let mut u: reqwest::Url = input.trim().parse().map_err(|_| "invalid URL".to_string())?;
    // Own the host before mutating `u` — `fragment()` borrows it immutably.
    let host_override = u.fragment().and_then(|frag| {
        frag.trim_start_matches('?')
            .split('&')
            .find_map(|kv| kv.strip_prefix("host="))
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
    });
    if let Some(host) = host_override {
        u.set_host(Some(&host))
            .map_err(|_| "invalid host override".to_string())?;
    }
    u.set_fragment(None);
    u.set_query(None);
    let path = u.path().trim_end_matches('/').to_string();
    u.set_path(&format!("{path}/sing-box")); // Marzban client-type suffix
    Ok(u.to_string())
}

async fn fetch_marzban(url: &str) -> Result<SubscriptionPayload, String> {
    let sb_url = parse_sub_url(&marzban_singbox_url(url)?)?;
    let resp = reqwest::get(sb_url).await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!(
            "not a Chatte or Marzban subscription (sing-box fetch got {})",
            resp.status().as_u16()
        ));
    }
    let config = resp.text().await.map_err(|e| format!("bad response: {e}"))?;
    singbox::validate_config(&config)?;
    // The whole Marzban sub is one connectable entry; sing-box's own
    // selector/urltest picks the node.
    Ok(SubscriptionPayload {
        expires: None, // ponytail: Marzban expiry lives in the subscription-userinfo header; show later
        servers: vec![ServerConfig {
            id: "marzban".into(),
            name: "Marzban".into(),
            country: String::new(),
            city: String::new(),
            protocol: "singbox".into(),
            config,
        }],
    })
}

#[tauri::command]
async fn set_subscription(url: String, state: State<'_, Shared>) -> Result<AppStatus, String> {
    let payload = fetch_subscription(&url).await?;
    store::save_subscription_url(&url)?;
    let mut st = state.lock().unwrap();
    st.expires = payload.expires;
    st.servers = payload.servers;
    Ok(status_of(&st))
}

#[tauri::command]
async fn refresh_servers(state: State<'_, Shared>) -> Result<AppStatus, String> {
    let url = store::load_subscription_url().ok_or("no subscription configured")?;
    let payload = fetch_subscription(&url).await?;
    let mut st = state.lock().unwrap();
    st.expires = payload.expires;
    st.servers = payload.servers;
    Ok(status_of(&st))
}

#[tauri::command]
fn connect(server_id: String, state: State<'_, Shared>) -> Result<AppStatus, String> {
    let mut st = state.lock().unwrap();
    let server = st
        .servers
        .iter()
        .find(|s| s.id == server_id)
        .ok_or("unknown server")?
        .clone();
    match server.protocol.as_str() {
        "wireguard" => vpn::connect(&server.config)?,
        "singbox" => singbox::connect(&server.config)?, // Marzban VLESS/VMess/Trojan/SS
        other => return Err(format!("{other} is not supported yet")),
    }
    st.connected_server = Some(server_id);
    Ok(status_of(&st))
}

/// Best-effort stop of whichever engine is up. Each call is a no-op if that
/// engine isn't running, so we don't need to know which one was active.
fn teardown_engines() {
    let _ = singbox::disconnect();
    let _ = vpn::disconnect();
}

#[tauri::command]
fn disconnect(state: State<'_, Shared>) -> Result<AppStatus, String> {
    teardown_engines();
    let mut st = state.lock().unwrap();
    st.connected_server = None;
    Ok(status_of(&st))
}

#[tauri::command]
fn status(state: State<'_, Shared>) -> AppStatus {
    let mut st = state.lock().unwrap();
    if st.connected_server.is_some() && !engine_connected(&st) {
        st.connected_server = None; // tunnel died out from under us
    }
    status_of(&st)
}

#[tauri::command]
async fn public_ip() -> Result<String, String> {
    let resp = reqwest::get("https://api.ipify.org")
        .await
        .map_err(|e| e.to_string())?;
    resp.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
fn forget_subscription(state: State<'_, Shared>) -> Result<(), String> {
    teardown_engines();
    store::clear_subscription_url()?;
    *state.lock().unwrap() = AppState::default();
    Ok(())
}

/// Is the engine backing the currently-selected server actually up?
fn engine_connected(st: &AppState) -> bool {
    let protocol = st
        .connected_server
        .as_deref()
        .and_then(|id| st.servers.iter().find(|s| s.id == id))
        .map(|s| s.protocol.as_str());
    match protocol {
        Some("singbox") => singbox::is_connected(),
        Some(_) => vpn::is_connected(),
        None => false,
    }
}

fn status_of(st: &AppState) -> AppStatus {
    let connected = st.connected_server.is_some() && engine_connected(st);
    AppStatus {
        has_subscription: st.expires.is_some() || store::load_subscription_url().is_some(),
        expires: st.expires.clone(),
        servers: to_info(&st.servers),
        connected,
        connected_server: st.connected_server.clone(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Shared::default())
        .invoke_handler(tauri::generate_handler![
            set_subscription,
            refresh_servers,
            connect,
            disconnect,
            status,
            public_ip,
            forget_subscription
        ])
        .run(tauri::generate_context!())
        .expect("error while running chatte vpn");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marzban_url_honours_host_override_and_appends_suffix() {
        let got = marzban_singbox_url(
            "https://www.google.com/sub/TOKEN#?resolve-address=www.google.com&host=zeus.run.app",
        )
        .unwrap();
        assert_eq!(got, "https://zeus.run.app/sub/TOKEN/sing-box");
    }

    #[test]
    fn marzban_url_plain_and_trailing_slash() {
        assert_eq!(
            marzban_singbox_url("https://panel.example/sub/TOKEN/").unwrap(),
            "https://panel.example/sub/TOKEN/sing-box"
        );
    }
}
