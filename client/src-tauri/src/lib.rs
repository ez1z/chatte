//! Tauri commands. Rule: WireGuard configs and the subscription token stay in
//! this process; the webview only ever sees server metadata and status.

mod store;
mod vpn;

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

#[derive(Clone, Deserialize)]
struct SubscriptionPayload {
    expires: String,
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

async fn fetch_subscription(url: &str) -> Result<SubscriptionPayload, String> {
    let url: reqwest::Url = url.trim().parse().map_err(|_| "invalid URL".to_string())?;
    match url.scheme() {
        "https" => {}
        // ponytail: http allowed for localhost dev only; TLS everywhere else.
        "http" if matches!(url.host_str(), Some("localhost" | "127.0.0.1")) => {}
        _ => return Err("subscription URL must be https".into()),
    }
    let resp = reqwest::get(url).await.map_err(|e| e.to_string())?;
    match resp.status().as_u16() {
        200 => resp.json().await.map_err(|e| format!("bad response: {e}")),
        403 => Err("subscription expired".into()),
        404 => Err("subscription not found — check the URL".into()),
        s => Err(format!("server error ({s})")),
    }
}

#[tauri::command]
async fn set_subscription(url: String, state: State<'_, Shared>) -> Result<AppStatus, String> {
    let payload = fetch_subscription(&url).await?;
    store::save_subscription_url(&url)?;
    let mut st = state.lock().unwrap();
    st.expires = Some(payload.expires);
    st.servers = payload.servers;
    Ok(status_of(&st))
}

#[tauri::command]
async fn refresh_servers(state: State<'_, Shared>) -> Result<AppStatus, String> {
    let url = store::load_subscription_url().ok_or("no subscription configured")?;
    let payload = fetch_subscription(&url).await?;
    let mut st = state.lock().unwrap();
    st.expires = Some(payload.expires);
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
        .ok_or("unknown server")?;
    if server.protocol != "wireguard" {
        return Err(format!("{} is not supported yet", server.protocol)); // Xray: Phase 2
    }
    vpn::connect(&server.config)?;
    st.connected_server = Some(server_id);
    Ok(status_of(&st))
}

#[tauri::command]
fn disconnect(state: State<'_, Shared>) -> Result<AppStatus, String> {
    vpn::disconnect()?;
    let mut st = state.lock().unwrap();
    st.connected_server = None;
    Ok(status_of(&st))
}

#[tauri::command]
fn status(state: State<'_, Shared>) -> AppStatus {
    let mut st = state.lock().unwrap();
    if st.connected_server.is_some() && !vpn::is_connected() {
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
    let _ = vpn::disconnect();
    store::clear_subscription_url()?;
    *state.lock().unwrap() = AppState::default();
    Ok(())
}

fn status_of(st: &AppState) -> AppStatus {
    let connected = st.connected_server.is_some() && vpn::is_connected();
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
