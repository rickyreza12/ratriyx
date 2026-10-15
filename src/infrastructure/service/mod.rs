mod sockets;
mod systemd;

pub use sockets::listening;
pub use systemd::{control, tor_bootstrap_percent, tor_state, unit_active};

use crate::domain::error::{Error, Result};

pub const TOR_INSTANCE: &str = "tor@default";
pub const TOR_MASTER: &str = "tor";
pub const PRIVOXY: &str = "privoxy";
pub const ALLOWED_UNITS: [&str; 3] = [TOR_INSTANCE, TOR_MASTER, PRIVOXY];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorState {
    pub instance_running: bool,
    pub instance_sub: String,
    pub master_state: String,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub addr: String,
    pub port: u16,
    pub process: Option<String>,
}

impl Listener {
    pub fn is_loopback(&self) -> bool {
        is_loopback_addr(&self.addr)
    }
}

/// Loopback check for `ss`/`netstat` local-address fields. Accepts
/// `127.0.0.1`, `::1`, `[::1]`, `localhost`, and wildcard forms as
/// explicitly not loopback.
pub fn is_loopback_addr(addr: &str) -> bool {
    let a = addr
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if a == "127.0.0.1" || a == "::1" || a == "localhost" {
        return true;
    }
    if let Ok(ip) = a.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    false
}

pub fn is_wildcard_addr(addr: &str) -> bool {
    let a = addr
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    a == "0.0.0.0" || a == "::" || a == "*"
}

/// Listener lookup that preserves the bind address, so diagnostics can
/// distinguish loopback, wildcard, and absent sockets.
pub fn find_listener(listeners: &[Listener], port: u16) -> Option<&Listener> {
    listeners.iter().find(|l| l.port == port)
}

pub fn validate(action: &str, unit: &str) -> Result<()> {
    if !matches!(action, "start" | "stop" | "restart" | "status") {
        return Err(Error::Usage(format!("unknown service action {action}")));
    }
    if !ALLOWED_UNITS.contains(&unit) {
        return Err(Error::Usage(format!(
            "unit {unit} is not managed by ratriyx; allowed: {}",
            ALLOWED_UNITS.join(", ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_unit_is_rejected_before_anything_runs() {
        assert!(validate("stop", "sshd").is_err());
        assert!(validate("kill", "privoxy").is_err());
    }
}
