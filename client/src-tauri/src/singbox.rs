//! sing-box controller: drives a bundled `sing-box.exe` in TUN mode for
//! Marzban-style subscriptions (VLESS/VMess/Trojan/Shadowsocks). Mirrors
//! `vpn.rs`: sing-box owns the TUN adapter, routing and DNS via `auto_route`,
//! so traffic is captured system-wide — the WireGuard-parity behaviour.
//!
//! Unlike WireGuard (a Windows service), sing-box runs as a child process we
//! own; we keep the handle here and kill it on disconnect.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;

static SINGBOX: Mutex<Option<Child>> = Mutex::new(None);

fn app_dir() -> Result<PathBuf, String> {
    let base = std::env::var("LOCALAPPDATA").map_err(|e| e.to_string())?;
    let dir = PathBuf::from(base).join("ChatteVPN");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn conf_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("singbox.json"))
}

/// Single-exe build: sing-box.exe + wintun.dll are baked in and extracted
/// once (rewritten only when the size differs — a cheap version check).
#[cfg(embed_singbox)]
fn singbox_exe() -> Result<PathBuf, String> {
    const SB: &[u8] = include_bytes!("../bin/sing-box.exe");
    const WT: &[u8] = include_bytes!("../bin/wintun.dll");
    let dir = app_dir()?;
    write_if_stale(&dir.join("wintun.dll"), WT)?; // must sit beside sing-box.exe
    let exe = dir.join("sing-box.exe");
    write_if_stale(&exe, SB)?;
    Ok(exe)
}

#[cfg(embed_singbox)]
fn write_if_stale(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let stale = std::fs::metadata(path)
        .map(|m| m.len() != bytes.len() as u64)
        .unwrap_or(true);
    if stale {
        std::fs::write(path, bytes).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Fallback build: expect sing-box.exe next to the app or on PATH.
#[cfg(not(embed_singbox))]
fn singbox_exe() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let local = dir.join("sing-box.exe");
            if local.exists() {
                return Ok(local);
            }
        }
    }
    Ok(PathBuf::from("sing-box.exe")) // rely on PATH
}

/// The backend is semi-trusted — confirm this is a sing-box config with at
/// least one outbound before we run it.
pub fn validate_config(config: &str) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_str(config)
        .map_err(|_| "did not return a sing-box config".to_string())?;
    match v.get("outbounds").and_then(|o| o.as_array()) {
        Some(a) if !a.is_empty() => Ok(()),
        _ => Err("sing-box config has no outbounds".into()),
    }
}

/// Force a system-wide TUN inbound so every app's traffic is captured,
/// regardless of what inbound Marzban's template shipped. We keep Marzban's
/// outbounds/route/dns untouched.
/// ponytail: targets sing-box ≥1.10 (uses `address`); assumes Marzban's route
/// sends traffic to its proxy selector. Per-node picking via sing-box's clash
/// API is a later step — for now the config's own urltest/selector chooses.
fn inject_tun_inbound(config: &str) -> Result<String, String> {
    let mut v: serde_json::Value = serde_json::from_str(config).map_err(|e| e.to_string())?;
    v["inbounds"] = serde_json::json!([{
        "type": "tun",
        "tag": "chatte-tun",
        "address": ["172.19.0.1/30"],
        "auto_route": true,
        "strict_route": true,
        "stack": "mixed"
    }]);
    serde_json::to_string(&v).map_err(|e| e.to_string())
}

pub fn connect(config: &str) -> Result<(), String> {
    validate_config(config)?;
    let with_tun = inject_tun_inbound(config)?;
    let _ = disconnect(); // tear down any stale instance first

    // ponytail: plaintext config on disk while connected, deleted on disconnect;
    // DPAPI + restrictive ACL when the service broker lands (same ceiling as WG).
    let path = conf_path()?;
    std::fs::write(&path, with_tun.as_bytes()).map_err(|e| e.to_string())?;

    let exe = singbox_exe()?;
    let mut cmd = Command::new(&exe);
    cmd.args(["run", "-c", &path.to_string_lossy()]);
    cmd.current_dir(app_dir()?); // so sing-box finds wintun.dll beside itself
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW — no console popup
    }
    let child = cmd.spawn().map_err(|e| {
        let _ = std::fs::remove_file(&path);
        format!("failed to start sing-box ({e}). Put sing-box.exe next to the app or on PATH — https://sing-box.sagernet.org")
    })?;
    *SINGBOX.lock().unwrap() = Some(child);

    // sing-box exits fast on a bad config or missing admin (TUN needs elevation);
    // surface that instead of reporting a phantom "connected".
    std::thread::sleep(std::time::Duration::from_millis(400));
    if !is_connected() {
        let _ = disconnect();
        return Err(
            "sing-box exited immediately — bad config, or the app isn't running as Administrator"
                .into(),
        );
    }
    Ok(())
}

pub fn disconnect() -> Result<(), String> {
    if let Some(mut child) = SINGBOX.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Ok(p) = conf_path() {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

pub fn is_connected() -> bool {
    let mut guard = SINGBOX.lock().unwrap();
    match guard.as_mut() {
        Some(child) => match child.try_wait() {
            Ok(None) => true, // still running
            _ => {
                *guard = None; // exited or errored
                false
            }
        },
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_injects_tun() {
        let cfg = r#"{"outbounds":[{"type":"vless","tag":"proxy"}]}"#;
        assert!(validate_config(cfg).is_ok());
        assert!(validate_config("garbage").is_err());
        assert!(validate_config(r#"{"outbounds":[]}"#).is_err());

        let out = inject_tun_inbound(cfg).unwrap();
        assert!(out.contains("\"type\":\"tun\""));
        assert!(out.contains("\"tag\":\"proxy\"")); // outbounds preserved
    }
}
