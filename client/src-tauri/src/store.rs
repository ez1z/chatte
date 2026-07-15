//! Subscription URL storage in Windows Credential Manager (DPAPI-backed).
//! The URL embeds the token, so it never touches disk in plaintext.

use keyring::Entry;

const SERVICE: &str = "chatte-vpn";
const KEY: &str = "subscription-url";

fn entry() -> Result<Entry, String> {
    Entry::new(SERVICE, KEY).map_err(|e| e.to_string())
}

pub fn save_subscription_url(url: &str) -> Result<(), String> {
    entry()?.set_password(url).map_err(|e| e.to_string())
}

pub fn load_subscription_url() -> Option<String> {
    entry().ok()?.get_password().ok()
}

pub fn clear_subscription_url() -> Result<(), String> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
