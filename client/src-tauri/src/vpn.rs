//! WireGuard controller: drives the official WireGuard for Windows tunnel
//! service. The WG service owns the Wintun adapter, routing table, and DNS —
//! system-wide traffic (browsers, terminals, WSL) routes through it because
//! the config uses AllowedIPs = 0.0.0.0/0.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

pub const TUNNEL_NAME: &str = "Chatte";

fn wireguard_exe() -> Result<PathBuf, String> {
    let candidates = [
        r"C:\Program Files\WireGuard\wireguard.exe",
        r"C:\Program Files (x86)\WireGuard\wireguard.exe",
    ];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .ok_or_else(|| {
            "WireGuard is not installed. Install it from https://www.wireguard.com/install/".into()
        })
}

fn conf_path() -> Result<PathBuf, String> {
    let base = std::env::var("LOCALAPPDATA").map_err(|e| e.to_string())?;
    let dir = PathBuf::from(base).join("ChatteVPN");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join(format!("{TUNNEL_NAME}.conf")))
}

fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(format!("{stdout}{stderr}").trim().to_string())
    }
}

/// Validate this looks like a WireGuard config before handing it to the
/// service — the backend is semi-trusted, don't install arbitrary blobs.
fn validate_config(config: &str) -> Result<(), String> {
    let has = |section: &str| config.lines().any(|l| l.trim() == section);
    if !has("[Interface]") || !has("[Peer]") {
        return Err("server returned an invalid WireGuard config".into());
    }
    Ok(())
}

pub fn connect(config: &str) -> Result<(), String> {
    validate_config(config)?;
    let wg = wireguard_exe()?;
    let _ = disconnect(); // tear down any stale tunnel first

    // ponytail: plaintext conf on disk while connected, deleted on disconnect;
    // DPAPI-encrypted conf + restrictive ACL when we split out the service broker.
    let path = conf_path()?;
    let mut f = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    f.write_all(config.as_bytes()).map_err(|e| e.to_string())?;
    drop(f);

    let res = run(Command::new(&wg).args(["/installtunnelservice", &path.to_string_lossy()]));
    if let Err(e) = res {
        let _ = std::fs::remove_file(&path);
        if e.is_empty() {
            return Err(
                "failed to install tunnel service (is the app running as Administrator?)".into(),
            );
        }
        return Err(e);
    }
    Ok(())
}

pub fn disconnect() -> Result<(), String> {
    let wg = wireguard_exe()?;
    let res = run(Command::new(&wg).args(["/uninstalltunnelservice", TUNNEL_NAME]));
    if let Ok(path) = conf_path() {
        let _ = std::fs::remove_file(path);
    }
    res.map(|_| ())
}

pub fn is_connected() -> bool {
    // The tunnel service exists only while a tunnel is installed.
    Command::new("sc")
        .args(["query", &format!("WireGuardTunnel${TUNNEL_NAME}")])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage_config() {
        assert!(validate_config("hello").is_err());
        assert!(validate_config("[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y").is_ok());
    }
}
